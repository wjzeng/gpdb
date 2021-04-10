/*-------------------------------------------------------------------------
 * tupser.c
 *	   Functions for serializing and deserializing a heap tuple.
 *
 * Portions Copyright (c) 2005-2008, Greenplum inc
 * Portions Copyright (c) 2012-Present Pivotal Software, Inc.
 *
 *
 * IDENTIFICATION
 *	    src/backend/cdb/motion/tupser.c
 *
 *      Reviewers: jzhang, ftian, tkordas
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/htup.h"
#include "catalog/pg_type.h"
#include "cdb/cdbmotion.h"
#include "cdb/cdbsrlz.h"
#include "cdb/tupser.h"
#include "cdb/cdbvars.h"
#include "libpq/pqformat.h"
#include "storage/smgr.h"
#include "utils/acl.h"
#include "utils/date.h"
#include "utils/numeric.h"
#include "utils/memutils.h"
#include "utils/builtins.h"
#include "utils/syscache.h"
#include "utils/typcache.h"

#include "access/memtup.h"

/*
 * Transient record types table is sent to upsteam via a specially constructed
 * tuple, on receiving side it can distinguish it from real tuples by checking
 * below magic attributes in the header:
 *
 * - tuplen has MEMTUP_LEAD_BIT unset, so it's considered as a heap tuple;
 * - natts is set to RECORD_CACHE_MAGIC_NATTS;
 * - infomask is set to RECORD_CACHE_MAGIC_INFOMASK.
 */
#define RECORD_CACHE_MAGIC_NATTS	0xffff
#define RECORD_CACHE_MAGIC_INFOMASK	0xffff

/* A MemoryContext used within the tuple serialize code, so that freeing of
 * space is SUPAFAST.  It is initialized in the first call to InitSerTupInfo()
 * since that must be called before any tuple serialization or deserialization
 * work can be done.
 */
static MemoryContext s_tupSerMemCtxt = NULL;

static void addByteStringToChunkList(TupleChunkList tcList, char *data, int datalen, TupleChunkListCache *cache);

#define addCharToChunkList(tcList, x, c)							\
	do															\
	{															\
		char y = (x);											\
		addByteStringToChunkList((tcList), (char *)&y, sizeof(y), (c));	\
	} while (0)

#define addInt32ToChunkList(tcList, x, c)							\
	do															\
	{															\
		int32 y = (x);											\
		addByteStringToChunkList((tcList), (char *)&y, sizeof(y), (c));	\
	} while (0)


static inline void
addPadding(TupleChunkList tcList, TupleChunkListCache *cache, int size)
{
	while (size++ & (TUPLE_CHUNK_ALIGN-1))
		addCharToChunkList(tcList,0,cache);
}

static inline void
skipPadding(StringInfo serialTup)
{
	serialTup->cursor = TYPEALIGN(TUPLE_CHUNK_ALIGN,serialTup->cursor);
}

/*
 * stringInfoGetInt32
 *
 * Pull a 4-byte integer out of str, at the current cursor location.  The
 * cursor is then incremented by 4.  If there is not 4 bytes left between the
 * cursor and the end of the string, an error is reported.
 *
 * The input is expected to be in the current architecture's byte-ordering.
 *
 * Hopefully this is faster than the stuff in stringinfo.c or pqformat.c!
 */
static inline int32
stringInfoGetInt32(StringInfo str)
{
	int32		res;

	/* Make sure there are enough bytes left. */
	if (str->len - str->cursor < 4)
	{
		ereport(ERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION),
						errmsg("deserialize data underflow")));
	}

	/*
	 * Pull out the int32.	We cast the pointer to the next part of the data
	 * to an int32 pointer, and just retrieve the integer from that location
	 * in the array.
	 */
	res = *((int32 *) (str->data + str->cursor));

	/* Update the cursor. */
	str->cursor += 4;

	return res;
}

/* Look up all of the information that SerializeTuple() and DeserializeTuple()
 * need to perform their jobs quickly.	Also, scratchpad space is allocated
 * for serialization and desrialization of datum values, and for formation/
 * deformation of tuples themselves.
 *
 * NOTE:  This function allocates various data-structures, but it assumes that
 *		  the current memory-context is acceptable.  So the caller should set
 *		  the desired memory-context before calling this function.
 */
void
InitSerTupInfo(TupleDesc tupdesc, SerTupInfo * pSerInfo)
{
	int			i,
				numAttrs;

	AssertArg(tupdesc != NULL);
	AssertArg(pSerInfo != NULL);

	if (s_tupSerMemCtxt == NULL)
	{
		/* Create tuple-serialization memory context. */
		s_tupSerMemCtxt =
			AllocSetContextCreate(TopMemoryContext,
								  "TupSerMemCtxt",
								  ALLOCSET_DEFAULT_INITSIZE,	/* always have some memory */
								  ALLOCSET_DEFAULT_INITSIZE,
								  ALLOCSET_DEFAULT_MAXSIZE);
	}

	/* Set contents to all 0, just to make things clean and easy. */
	memset(pSerInfo, 0, sizeof(SerTupInfo));

	/* Store the tuple-descriptor so we can use it later. */
	pSerInfo->tupdesc = tupdesc;

	pSerInfo->chunkCache.len = 0;
	pSerInfo->chunkCache.items = NULL;

	pSerInfo->has_record_types = false;

	/*
	 * If we have some attributes, go ahead and prepare the information for
	 * each attribute in the descriptor.  Otherwise, we can return right away.
	 */
	numAttrs = tupdesc->natts;
	if (numAttrs <= 0)
		return;

	pSerInfo->myinfo = (SerAttrInfo *) palloc0(numAttrs * sizeof(SerAttrInfo));

	pSerInfo->values = (Datum *) palloc(numAttrs * sizeof(Datum));
	pSerInfo->nulls = (bool *) palloc(numAttrs * sizeof(bool));

	for (i = 0; i < numAttrs; i++)
	{
		SerAttrInfo *attrInfo = pSerInfo->myinfo + i;

		/*
		 * Get attribute's data-type Oid.  This lets us shortcut the comm
		 * operations for some attribute-types.
		 */
		attrInfo->atttypid = tupdesc->attrs[i]->atttypid;
		
		/*
		 * Serialization will be performed at a high level abstraction,
		 * we only care about whether it's toasted or pass-by-value or
		 * a CString, so only track the high level type information.
		 */
		{
			HeapTuple	typeTuple;
			Form_pg_type pt;

			typeTuple = SearchSysCache1(TYPEOID,
										ObjectIdGetDatum(attrInfo->atttypid));
			if (!HeapTupleIsValid(typeTuple))
				elog(ERROR, "cache lookup failed for type %u", attrInfo->atttypid);
			pt = (Form_pg_type) GETSTRUCT(typeTuple);
		
			/* Consider any non-basic types as potential containers of record types */
			if (pt->typtype != TYPTYPE_BASE)
				pSerInfo->has_record_types = true;

			if (!pt->typisdefined)
				ereport(ERROR,
						(errcode(ERRCODE_UNDEFINED_OBJECT),
						 errmsg("type %s is only a shell",
								format_type_be(attrInfo->atttypid))));
								
			attrInfo->typlen = pt->typlen;
			attrInfo->typbyval = pt->typbyval;

			ReleaseSysCache(typeTuple);
		}
	}
}


/* Free up storage in a previously initialized SerTupInfo struct. */
void
CleanupSerTupInfo(SerTupInfo * pSerInfo)
{
	AssertArg(pSerInfo != NULL);

	/*
	 * Free any old data.
	 *
	 * NOTE:  This works because data-structure was bzero()ed in init call.
	 */
	if (pSerInfo->myinfo != NULL)
		pfree(pSerInfo->myinfo);
	pSerInfo->myinfo = NULL;

	if (pSerInfo->values != NULL)
		pfree(pSerInfo->values);
	pSerInfo->values = NULL;

	if (pSerInfo->nulls != NULL)
		pfree(pSerInfo->nulls);
	pSerInfo->nulls = NULL;

	pSerInfo->tupdesc = NULL;

	while (pSerInfo->chunkCache.items != NULL)
	{
		TupleChunkListItem item;

		item = pSerInfo->chunkCache.items;
		pSerInfo->chunkCache.items = item->p_next;
		pfree(item);
	}
}

/*
 * When manipulating chunks before transmit, it is important to notice that the
 * tcItem's chunk_length field *includes* the 4-byte chunk header, but that the
 * length within the header itself does not. Getting the two confused results
 * heap overruns and that way lies pain.
 */
static void
addByteStringToChunkList(TupleChunkList tcList, char *data, int datalen, TupleChunkListCache *chunkCache)
{
	TupleChunkListItem tcItem;
	int			remain,
				curSize,
				available,
				copyLen;
	char	   *pos;

	AssertArg(tcList != NULL);
	AssertArg(tcList->p_last != NULL);
	AssertArg(data != NULL);

	/* Add onto last chunk, lists always start with one chunk */
	tcItem = tcList->p_last;

	/* we'll need to add chunks */
	remain = datalen;
	pos = data;
	do
	{
		curSize = tcItem->chunk_length;

		available = tcList->max_chunk_length - curSize;
		copyLen = Min(available, remain);
		if (copyLen > 0)
		{
			/*
			 * make sure we don't stomp on the serialized header, chunk_length
			 * already accounts for it
			 */
			memcpy(tcItem->chunk_data + curSize, pos, copyLen);

			remain -= copyLen;
			pos += copyLen;
			tcList->serialized_data_length += copyLen;
			curSize += copyLen;

			SetChunkDataSize(tcItem->chunk_data, curSize - TUPLE_CHUNK_HEADER_SIZE);
			tcItem->chunk_length = curSize;
		}

		if (remain == 0)
			break;

		tcItem = getChunkFromCache(chunkCache);
		tcItem->chunk_length = TUPLE_CHUNK_HEADER_SIZE;
		SetChunkType(tcItem->chunk_data, TC_PARTIAL_MID);
		appendChunkToTCList(tcList, tcItem);
	} while (remain != 0);

	return;
}

typedef struct TupSerHeader
{
	uint32		tuplen;	
	uint16		natts;			/* number of attributes */
	uint16		infomask;		/* various flag bits */
} TupSerHeader;

/*
 * Convert RecordCache into a byte-sequence, and store it directly
 * into a chunklist for transmission.
 *
 * This code is based on the printtup_internal_20() function in printtup.c.
 */
void
SerializeRecordCacheIntoChunks(SerTupInfo *pSerInfo,
							   TupleChunkList tcList,
							   MotionConn *conn)
{
	TupleChunkListItem tcItem = NULL;
	MemoryContext oldCtxt;
	TupSerHeader tsh;
	List *typelist = NULL;
	int size = -1;
	char * buf = NULL;

	AssertArg(tcList != NULL);
	AssertArg(pSerInfo != NULL);

	/* get ready to go */
	tcList->p_first = NULL;
	tcList->p_last = NULL;
	tcList->num_chunks = 0;
	tcList->serialized_data_length = 0;
	tcList->max_chunk_length = Gp_max_tuple_chunk_size;

	tcItem = getChunkFromCache(&pSerInfo->chunkCache);

	/* assume that we'll take a single chunk */
	SetChunkType(tcItem->chunk_data, TC_WHOLE);
	tcItem->chunk_length = TUPLE_CHUNK_HEADER_SIZE;
	appendChunkToTCList(tcList, tcItem);

	AssertState(s_tupSerMemCtxt != NULL);

	/*
	 * To avoid inconsistency of record cache between sender and receiver in
	 * the same motion, send the serialized record cache to receiver before the
	 * first tuple is sent, the receiver is responsible for registering the
	 * records to its own local cache and remapping the typmod of tuples sent
	 * by sender.
	 */
	oldCtxt = MemoryContextSwitchTo(s_tupSerMemCtxt);
	typelist = build_tuple_node_list(conn->sent_record_typmod);
	buf = serializeNode((Node *) typelist, &size, NULL);
	MemoryContextSwitchTo(oldCtxt);

	tsh.tuplen = sizeof(TupSerHeader) + size;

	/*
	 * we use natts==0xffff and infomask==0xffff to identify this special
	 * tuple which actually carry the serialized record cache table.
	 */
	tsh.natts = RECORD_CACHE_MAGIC_NATTS;
	tsh.infomask = RECORD_CACHE_MAGIC_INFOMASK;

	addByteStringToChunkList(tcList,
							 (char *)&tsh,
							 sizeof(TupSerHeader),
							 &pSerInfo->chunkCache);
	addByteStringToChunkList(tcList, buf, size, &pSerInfo->chunkCache);
	addPadding(tcList, &pSerInfo->chunkCache, size);

	/*
	 * if we have more than 1 chunk we have to set the chunk types on our
	 * first chunk and last chunk
	 */
	if (tcList->num_chunks > 1)
	{
		TupleChunkListItem first,
			last;

		first = tcList->p_first;
		last = tcList->p_last;

		Assert(first != NULL);
		Assert(first != last);
		Assert(last != NULL);

		SetChunkType(first->chunk_data, TC_PARTIAL_START);
		SetChunkType(last->chunk_data, TC_PARTIAL_END);

		/*
		 * any intervening chunks are already set to TC_PARTIAL_MID when
		 * allocated
		 */
	}

	return;
}

static bool
CandidateForSerializeDirect(int16 targetRoute, struct directTransportBuffer *b)
{
	return targetRoute != BROADCAST_SEGIDX && b->pri != NULL && b->prilen > TUPLE_CHUNK_HEADER_SIZE;
}

/*
 *
 * First try to serialize a tuple directly into a buffer.
 *
 * We're called with at least enough space for a tuple-chunk-header.
 *
 * Convert a HeapTuple into a byte-sequence, and store it directly
 * into a chunklist for transmission.
 *
 * This code is based on the printtup_internal_20() function in printtup.c.
 */
int
SerializeTuple(TupleTableSlot *slot, SerTupInfo *pSerInfo, struct directTransportBuffer *b, TupleChunkList tcList, int16 targetRoute)
{
	int			natts;
	int			dataSize = TUPLE_CHUNK_HEADER_SIZE;
	TupleDesc	tupdesc;
	TupleChunkListItem tcItem = NULL;

	AssertArg(pSerInfo != NULL);
	AssertArg(b != NULL);

	tupdesc = pSerInfo->tupdesc;
	natts = tupdesc->natts;

	if (natts == 0 && CandidateForSerializeDirect(targetRoute, b))
	{
		/* TC_EMTPY is just one chunk */
		SetChunkType(b->pri, TC_EMPTY);
		SetChunkDataSize(b->pri, 0);

		return TUPLE_CHUNK_HEADER_SIZE;
	}

	tcList->p_first = NULL;
	tcList->p_last = NULL;
	tcList->num_chunks = 0;
	tcList->serialized_data_length = 0;
	tcList->max_chunk_length = Gp_max_tuple_chunk_size;

	if (slot->PRIVATE_tts_heaptuple == NULL ||
		(slot->PRIVATE_tts_heaptuple->t_data->t_infomask & HEAP_HASEXTERNAL) != 0)
	{
		/*
		 * Virtual or MemTuple slot, or a HeapTuple with toasted datums.
		 * Send it as a MemTuple.
		 */
		MemTuple	tuple;
		int			tupleSize;
		int			paddedSize;

		if (slot->PRIVATE_tts_memtuple &&
			!memtuple_get_hasext(slot->PRIVATE_tts_memtuple))
		{
			/* we can use the existing MemTuple as it is. */
			tuple = slot->PRIVATE_tts_memtuple;
		}
		else
		{
			MemoryContext oldContext;
			oldContext = MemoryContextSwitchTo(s_tupSerMemCtxt);
			slot_getallattrs(slot);
			tuple = memtuple_form_to(slot->tts_mt_bind, slot_get_values(slot), slot_get_isnull(slot),
									  NULL, NULL, true);
			MemoryContextSwitchTo(oldContext);
		}

		if (CandidateForSerializeDirect(targetRoute, b))
		{
			/*
			 * Here we first try to in-line serialize the tuple directly into
			 * buffer.
			 */
			tupleSize = memtuple_get_size(tuple);

			paddedSize = TYPEALIGN(TUPLE_CHUNK_ALIGN, tupleSize);

			if (paddedSize + TUPLE_CHUNK_HEADER_SIZE <= b->prilen)
			{
				/* will fit. */
				memcpy(b->pri + TUPLE_CHUNK_HEADER_SIZE, tuple, tupleSize);
				memset(b->pri + TUPLE_CHUNK_HEADER_SIZE + tupleSize, 0, paddedSize - tupleSize);

				dataSize += paddedSize;

				SetChunkType(b->pri, TC_WHOLE);
				SetChunkDataSize(b->pri, dataSize - TUPLE_CHUNK_HEADER_SIZE);
				return dataSize;
			}
		}

		/*
		 * If direct in-line serialization failed then we fallback to chunked
		 * out-of-line serialization.
		 */
		tcItem = getChunkFromCache(&pSerInfo->chunkCache);
		SetChunkType(tcItem->chunk_data, TC_WHOLE);
		tcItem->chunk_length = TUPLE_CHUNK_HEADER_SIZE;
		appendChunkToTCList(tcList, tcItem);

		AssertState(s_tupSerMemCtxt != NULL);

		addByteStringToChunkList(tcList, (char *) tuple, memtuple_get_size(tuple), &pSerInfo->chunkCache);
		addPadding(tcList, &pSerInfo->chunkCache, memtuple_get_size(tuple));

		MemoryContextReset(s_tupSerMemCtxt);
	}
	else
	{
		/* HeapTuple that doesn't require detoasting */
		HeapTuple	tuple = slot->PRIVATE_tts_heaptuple;
		TupSerHeader tsh;
		unsigned int datalen;
		unsigned int nullslen;

		HeapTupleHeader t_data = tuple->t_data;

		datalen = tuple->t_len - t_data->t_hoff;
		if (HeapTupleHasNulls(tuple))
			nullslen = BITMAPLEN(HeapTupleHeaderGetNatts(t_data));
		else
			nullslen = 0;

		tsh.tuplen = sizeof(TupSerHeader) + TYPEALIGN(TUPLE_CHUNK_ALIGN, nullslen) + datalen;
		tsh.natts = HeapTupleHeaderGetNatts(t_data);
		tsh.infomask = t_data->t_infomask;

		if (CandidateForSerializeDirect(targetRoute, b))
		{
			/*
			 * Here we first try to in-line serialize the tuple directly into
			 * buffer.
			 */
			if (dataSize + tsh.tuplen <= b->prilen)
			{
				unsigned char *pos;

				pos = b->pri + TUPLE_CHUNK_HEADER_SIZE;

				memcpy(pos, (char *) &tsh, sizeof(TupSerHeader));
				pos += sizeof(TupSerHeader);

				if (nullslen)
				{
					memcpy(pos, (char *) t_data->t_bits, nullslen);
					pos += nullslen;
					memset(pos, 0, TYPEALIGN(TUPLE_CHUNK_ALIGN, nullslen) - nullslen);
					pos += TYPEALIGN(TUPLE_CHUNK_ALIGN, nullslen) - nullslen;
				}

				memcpy(pos, (char *) t_data + t_data->t_hoff, datalen);
				pos += datalen;
				memset(pos, 0, TYPEALIGN(TUPLE_CHUNK_ALIGN, datalen) - datalen);
				pos += TYPEALIGN(TUPLE_CHUNK_ALIGN, datalen) - datalen;

				dataSize += tsh.tuplen;

				SetChunkType(b->pri, TC_WHOLE);
				SetChunkDataSize(b->pri, dataSize - TUPLE_CHUNK_HEADER_SIZE);
				return dataSize;
			}
		}

		/*
		 * If direct in-line serialization failed then we fallback to chunked
		 * out-of-line serialization.
		 */
		tcItem = getChunkFromCache(&pSerInfo->chunkCache);
		SetChunkType(tcItem->chunk_data, TC_WHOLE);
		tcItem->chunk_length = TUPLE_CHUNK_HEADER_SIZE;
		appendChunkToTCList(tcList, tcItem);

		AssertState(s_tupSerMemCtxt != NULL);

		addByteStringToChunkList(tcList, (char *) &tsh, sizeof(TupSerHeader), &pSerInfo->chunkCache);

		if (nullslen)
		{
			addByteStringToChunkList(tcList, (char *) t_data->t_bits, nullslen, &pSerInfo->chunkCache);
			addPadding(tcList, &pSerInfo->chunkCache, nullslen);
		}

		addByteStringToChunkList(tcList, (char *) t_data + t_data->t_hoff, datalen, &pSerInfo->chunkCache);
		addPadding(tcList, &pSerInfo->chunkCache, datalen);
	}

	/*
	 * if we have more than 1 chunk we have to set the chunk types on our
	 * first chunk and last chunk
	 */
	if (tcList->num_chunks > 1)
	{
		TupleChunkListItem first,
			last;

		first = tcList->p_first;
		last = tcList->p_last;

		Assert(first != NULL);
		Assert(first != last);
		Assert(last != NULL);

		SetChunkType(first->chunk_data, TC_PARTIAL_START);
		SetChunkType(last->chunk_data, TC_PARTIAL_END);

		/*
		 * any intervening chunks are already set to TC_PARTIAL_MID when
		 * allocated
		 */
	}

	/*
	 * performed "out-of-line" serialization
	 */
	return 0;
}

/*
 * Reassemble and deserialize a list of tuple chunks, into a tuple.
 */
GenericTuple
CvtChunksToTup(TupleChunkList tcList, SerTupInfo *pSerInfo, TupleRemapper *remapper)
{
	StringInfoData serData;
	TupleChunkListItem tcItem;
	int			i;
	GenericTuple tup;
	TupleChunkType tcType;

	AssertArg(tcList != NULL);
	AssertArg(tcList->p_first != NULL);
	AssertArg(pSerInfo != NULL);

	tcItem = tcList->p_first;

	if (tcList->num_chunks == 1)
	{
		GetChunkType(tcItem, &tcType);

		if (tcType == TC_EMPTY)
		{
			/*
			 * the sender is indicating that there was a row with no attributes:
			 * return a NULL tuple
			 */
			clearTCList(NULL, tcList);

			return (GenericTuple)
				heap_form_tuple(pSerInfo->tupdesc, pSerInfo->values, pSerInfo->nulls);
		}
	}

	/*
	 * Dump all of the data in the tuple chunk list into a single StringInfo,
	 * so that we can convert it into a HeapTuple.	Check chunk types based on
	 * whether there is only one chunk, or multiple chunks.
	 *
	 * We know roughly how much space we'll need, allocate all in one go.
	 *
	 */
	initStringInfoOfSize(&serData, tcList->num_chunks * tcList->max_chunk_length);

	i = 0;
	do
	{
		/* Make sure that the type of this tuple chunk is correct! */

		GetChunkType(tcItem, &tcType);
		if (i == 0)
		{
			if (tcItem->p_next == NULL)
			{
				if (tcType != TC_WHOLE)
				{
					ereport(ERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION),
									errmsg("Single chunk's type must be TC_WHOLE.")));
				}
			}
			else
				/* tcItem->p_next != NULL */
			{
				if (tcType != TC_PARTIAL_START)
				{
					ereport(ERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION),
									errmsg("First chunk of collection must have type"
										   " TC_PARTIAL_START.")));
				}
			}
		}
		else
			/* i > 0 */
		{
			if (tcItem->p_next == NULL)
			{
				if (tcType != TC_PARTIAL_END)
				{
					ereport(ERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION),
									errmsg("Last chunk of collection must have type"
										   " TC_PARTIAL_END.")));
				}
			}
			else
				/* tcItem->p_next != NULL */
			{
				if (tcType != TC_PARTIAL_MID)
				{
					ereport(ERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION),
									errmsg("Last chunk of collection must have type"
										   " TC_PARTIAL_MID.")));
				}
			}
		}

		/* Copy this chunk into the tuple data.  Don't include the header! */
		appendBinaryStringInfo(&serData,
							   (const char *) GetChunkDataPtr(tcItem) + TUPLE_CHUNK_HEADER_SIZE,
							   tcItem->chunk_length - TUPLE_CHUNK_HEADER_SIZE);

		/* Go to the next chunk. */
		tcItem = tcItem->p_next;
		i++;
	}
	while (tcItem != NULL);

	/* we've finished with the TCList, free it now. */
	clearTCList(NULL, tcList);

	{
		TupSerHeader *tshp;
		unsigned int	datalen;
		unsigned int	nullslen;
		unsigned int	hoff;
		HeapTupleHeader t_data;
		char *pos = (char *)serData.data;

		tshp = (TupSerHeader *)pos;

		if (!(tshp->tuplen & MEMTUP_LEAD_BIT) &&
			tshp->natts == RECORD_CACHE_MAGIC_NATTS &&
			tshp->infomask == RECORD_CACHE_MAGIC_INFOMASK)
		{
			uint32		tuplen = tshp->tuplen & ~MEMTUP_LEAD_BIT;
			/* a special tuple with record type cache */
			List * typelist = (List *) deserializeNode(pos + sizeof(TupSerHeader),
													   tuplen - sizeof(TupSerHeader));

			TRHandleTypeLists(remapper, typelist);

			/* Free up memory we used. */
			pfree(serData.data);

			return NULL;
		}

		if ((tshp->tuplen & MEMTUP_LEAD_BIT) != 0)
		{
			uint32		tuplen = memtuple_size_from_uint32(tshp->tuplen);

			tup = (GenericTuple) palloc(tuplen);
			memcpy(tup, pos, tuplen);

			pos += TYPEALIGN(TUPLE_CHUNK_ALIGN,tuplen);
		}
		else
		{
			HeapTuple htup;

			pos += sizeof(TupSerHeader);

			/*
			 * Tuples with toasted elements should've been converted to MemTuples.
			 */
			Assert((tshp->infomask & HEAP_HASEXTERNAL) == 0);

			/* reconstruct lengths of null bitmap and data part */
			if (tshp->infomask & HEAP_HASNULL)
				nullslen = BITMAPLEN(tshp->natts);
			else
				nullslen = 0;

			if (tshp->tuplen < sizeof(TupSerHeader) + nullslen)
				ereport(ERROR, (errcode(ERRCODE_GP_INTERCONNECTION_ERROR),
								errmsg("Interconnect error: cannot convert chunks to a  heap tuple."),
								errdetail("tuple len %d < nullslen %d + headersize (%d)",
										  tshp->tuplen, nullslen, (int)sizeof(TupSerHeader))));

			datalen = tshp->tuplen - sizeof(TupSerHeader) - TYPEALIGN(TUPLE_CHUNK_ALIGN, nullslen);

			/* determine overhead size of tuple (should match heap_form_tuple) */
			hoff = offsetof(HeapTupleHeaderData, t_bits) + TYPEALIGN(TUPLE_CHUNK_ALIGN, nullslen);
			if (tshp->infomask & HEAP_HASOID)
				hoff += sizeof(Oid);
			hoff = MAXALIGN(hoff);

			/* Allocate the space in one chunk, like heap_form_tuple */
			htup = (HeapTuple) palloc(HEAPTUPLESIZE + hoff + datalen);
			tup = (GenericTuple) htup;

			t_data = (HeapTupleHeader) ((char *)htup + HEAPTUPLESIZE);

			/* make sure unused header fields are zeroed */
			MemSetAligned(t_data, 0, hoff);

			/* reconstruct the HeapTupleData fields */
			htup->t_len = hoff + datalen;
			ItemPointerSetInvalid(&(htup->t_self));
			htup->t_data = t_data;

			/* reconstruct the HeapTupleHeaderData fields */
			ItemPointerSetInvalid(&(t_data->t_ctid));
			HeapTupleHeaderSetNatts(t_data, tshp->natts);
			t_data->t_infomask = tshp->infomask & ~HEAP_XACT_MASK;
			t_data->t_infomask |= HEAP_XMIN_INVALID | HEAP_XMAX_INVALID;
			t_data->t_hoff = hoff;

			if (nullslen)
			{
				memcpy((void *)t_data->t_bits, pos, nullslen);
				pos += TYPEALIGN(TUPLE_CHUNK_ALIGN,nullslen);
			}

			/* does the tuple descriptor expect an OID ? Note: we don't
			 * have to set the oid itself, just the flag! (see heap_formtuple()) */
			if (pSerInfo->tupdesc->tdhasoid)		/* else leave infomask = 0 */
			{
				t_data->t_infomask |= HEAP_HASOID;
			}

			/* and now the data proper (it would be nice if we could just
			 * point our caller into our existing buffer in-place, but
			 * we'll leave that for another day) */
			memcpy((char *)t_data + hoff, pos, datalen);
		}
	}

	/* Free up memory we used. */
	pfree(serData.data);

	return tup;
}
