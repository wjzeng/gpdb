# GPOPT and ORCA code linting

## Tools

[clang-tidy]: https://clang.llvm.org/extra/clang-tidy/index.html
[clang-tidy.11]: https://releases.llvm.org/11.0.0/tools/clang/tools/extra/docs/clang-tidy/index.html

1. We are using [Clang-Tidy][clang-tidy].

1. We use the current stable release in CI, which is [version 11][clang-tidy.11].

1. To get started, a very small set of checks are run continuously, with an eye to expanding the set gradually as we modernize and improve the code base.

1. Unlike formatting, developers *can* run newer versions of clang-tidy locally and fix more warnings.

## How To

[JSONCompDB]:https://clang.llvm.org/docs/JSONCompilationDatabase.html 

We have a [convenience script](../../tools/tidy) for running clang-tidy.
This script needs the path to a directory containing the [compilation database][JSONCompDB] (`compile_commands.json`)


### Prerequisite

[GnuParallel]: https://www.gnu.org/software/parallel/ 

The script makes use of [GNU Parallel][GnuParallel] and `clang-tidy`.
To install them on macOS:

```
brew install parallel llvm
```

On Debian-derivative Linux distributions, you have more choices on the version of clang-tidy, e.g.:

```
apt-get install parallel clang-tidy-12
```

Alternatively `apt-get install clang-tidy` will give you a "default" version of `clang-tidy` from the distribution.

### Generating Build Directories With A Compilation Database

Here's an example of generating two build directories, `build.debug` and `build.release` at the root of Greenplum repository:

for debug build:

```
$ CXX=clang++ cmake -GNinja -Hsrc/backend/gporca -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Debug -Bbuild.debug
```

and release:

```
$ CXX=clang++ cmake -GNinja -Hsrc/backend/gporca -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo -Bbuild.release
```

### Checking

To check (it's unsurprising if we pass the check in one configuration but not another)

```
$ src/tools/tidy chk build.debug
```

and

```
$ src/tools/tidy chk build.release
```

Note that the script assumes the name of `clang-tidy` is `clang-tidy` and it can be found on your `PATH`.
So if you're (typically) using `clang-tidy` from Homebrew's LLVM package, you'll override that assumption by e.g.:

```
$ CLANG_TIDY=/usr/local/opt/llvm/bin/clang-tidy src/tools/tidy chk build.debug
```
