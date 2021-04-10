#!/usr/bin/python2

import optparse
import os
import shutil
import stat
import subprocess
import sys

from builds.GpBuild import GpBuild


def install_gpdb(dependency_name):
    status = subprocess.call("mkdir -p /usr/local/gpdb", shell=True)
    if status:
        return status
    status = subprocess.call(
        "tar -xzf " + dependency_name + "/*.tar.gz -C /usr/local/gpdb",
        shell=True)
    return status


def create_gpadmin_user():
    status = subprocess.call("gpdb_src/concourse/scripts/setup_gpadmin_user.bash")
    os.chmod('/bin/ping', os.stat('/bin/ping').st_mode | stat.S_ISUID)
    if status:
        return status


def copy_output():
    shutil.copyfile("gpdb_src/src/test/regress/regression.diffs", "icg_output/regression.diffs")
    shutil.copyfile("gpdb_src/src/test/regress/regression.out", "icg_output/regression.out")


def configure():
    p_env = os.environ.copy()
    p_env['LD_LIBRARY_PATH'] = '/usr/local/gpdb/lib'
    p_env['CFLAGS'] = '-I/usr/local/gpdb/include'
    p_env['CPPFLAGS'] = '-I/usr/local/gpdb/include'
    p_env['LDFLAGS'] = '-L/usr/local/gpdb/lib'
    return subprocess.call(["./configure",
                            "--enable-mapreduce",
                            "--with-gssapi",
                            "--with-perl",
                            "--with-libxml",
                            "--with-python",
                            "--with-libs=/usr/local/gpdb/lib",
                            "--with-includes=/usr/local/gpdb/include",
                            "--prefix=/usr/local/gpdb"], env=p_env, cwd="gpdb_src")


def main():
    parser = optparse.OptionParser()
    parser.add_option("--build_type", dest="build_type", default="RELEASE")
    parser.add_option("--mode",  choices=['orca', 'planner'])
    parser.add_option("--compiler", dest="compiler")
    parser.add_option("--cxxflags", dest="cxxflags")
    parser.add_option("--output_dir", dest="output_dir", default="install")
    parser.add_option("--gpdb_name", dest="gpdb_name")
    (options, args) = parser.parse_args()
    gp_build = GpBuild(options.mode)

    status = install_gpdb(options.gpdb_name)
    if status:
        return status
    status = configure()
    if status:
        return status
    status = create_gpadmin_user()
    if status:
        return status
    status = gp_build.unit_test()

    if status:
        return status
    if os.getenv("TEST_SUITE", "icg") == 'icw':
      status = gp_build.install_check('world')
    else:
      status = gp_build.install_check()
    if status:
        copy_output()
    return status


if __name__ == "__main__":
    sys.exit(main())
