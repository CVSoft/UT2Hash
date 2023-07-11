#!/usr/bin/env python3

import argparse
import hashlib
import os
import os.path
import sqlite3
import struct
import traceback
import zlib

from sys import modules, stdout, stderr, exc_info

# check if MD5 is available -- sometimes it isn't
if "md5" not in hashlib.algorithms_available:
    raise NotImplementedError("MD5 isn't available on this Python build!")

VERSION = 0x0100
PERIODICALLY_COMMIT = 100 # adjust to not destroy your drive

# useful console logging!

MIN_LEVEL = 4

def log(*args, level=3, sep=' '):
    """Console-log a message"""
    # negated levels are forced to display regardless of verbosity
    # it's only used in the interactive section
    if level == 4:
        prefix = "DEBUG:"
        file = stdout
    elif level == 3 or level == -3:
        prefix = "INFO :"
        file = stdout
    elif level == 2 or level == -2:
        prefix = "WARN :"
        file = stdout
    elif level == 1:
        prefix = "ERROR:"
        file = stderr
    elif level == 0:
        prefix = "FATAL:"
        file = stderr
    else:
        log("Invalid level", level=2)
    if level > MIN_LEVEL and level not in (-2, -3): return
    print(prefix, *args, sep=sep, file=file)


class Database(object):
    """Create sqlite3 db to store md5 hashes"""
    def __init__(self, fn="hashes.sqb"):
        log("Opening access to table", level=4)
        self.fn = fn
        self.conn = sqlite3.connect(fn)
        self.c = self.conn.cursor()
        self.count = 0
        self.force_casefold = False

    def __call__(self, fn):
        """convenience function for using `with`"""
        # is this legal?
        self.__init__(fn)
        return self

    def __enter__(self):
        """convenience function for using `with`"""
        return self

    def __exit__(self, *exc):
        """convenience function for using `with`"""
        self.close()

    def initialize(self, delete=False):
        """Create the table if we need to; otherwise, do nothing"""
        if delete:
            log("Deleting table contents by request", level=2)
            self.c.execute("DROP TABLE IF EXISTS hashes")
        log("Table initialized by request", level=4)
        self.c.execute("CREATE TABLE IF NOT EXISTS hashes(id INTEGER PRIMARY KEY, filename TEXT, size INTEGER, md5 TEXT);")
        self.c.execute("SELECT MAX(id) FROM hashes;")
        self.count = self.c.fetchone()[0]
        if self.count is None: self.count = 0
        self.count += 1 # go to next available index

    def put(self, fn, size, md5):
        """Put formatted data in the database"""
        assert len(md5) == 32, "Invalid MD5 length!"
        if self.force_casefold: fn = fn.casefold()
        self.c.execute("INSERT INTO hashes VALUES (?, ?, ?, ?);", \
                       (self.count, fn, size, md5))
        self.count += 1
        # periodically commit because i am paranoid
        if self.count % PERIODICALLY_COMMIT == 0: self.conn.commit()

    def commit(self):
        """Convenience accessor"""
        self.conn.commit()

    def close(self):
        """Commit to the database, and close the connection"""
        self.commit()
        try:
            self.conn.close()
            log("Closed database successfully", level=3)
        except:
            log("Failed to close database!", level=1)
        
    def find(self, md5):
        """Locate data in the database, and return all matches"""
        self.c.execute("SELECT filename, size, md5 FROM hashes WHERE md5=? ORDER BY filename COLLATE NOCASE;", (md5,))
        return self.c.fetchall() # possible performance considerations

    def find_by_name(self, filename):
        """Locate data in the database, and return all matches"""
        self.c.execute("SELECT filename, size, md5 FROM hashes WHERE filename=? ORDER BY filename COLLATE NOCASE;", (filename,))
        return self.c.fetchall() # ^

    def dump(self, raw=False):
        """Print (log) the whole table contents"""
        self.c.execute("SELECT filename, size, md5 FROM hashes ORDER BY filename;")
        if raw: return self.c.fetchall() # PERFORMANCE! should probably generate
        while True:
            row = self.c.fetchone()
            if not row: break # out of data
            log("fn={:s} size={:d} md5={:s}".format(*row), level=3)

    def count_rows(self):
        """Count number of entries in the database"""
        self.c.execute("SELECT COUNT(*) FROM hashes;")
        row = self.c.fetchone()[0]
        if row is None: return 0
        return row

    def find_duplicates(self):
        """List all duplicate rows in the database; case sensitive"""
        self.c.execute("SELECT filename, md5, COUNT(*) FROM hashes GROUP BY filename, md5 HAVING COUNT(*) > 1;")
        while True:
            row = self.c.fetchone()
            if not row: break # out of data
            log("File {:s} (md5={:s}) appears {:d} times".format(*row), level=3)

    def find_duplicate_hashes(self, raw=False):
        """List all duplicate files in the database"""
        self.c.execute("SELECT filename, md5, COUNT(md5) FROM hashes GROUP BY md5 HAVING COUNT(md5) > 1;")
        while True:
            row = self.c.fetchone()
            if not row: break # out of data
            log("File {:s} (md5={:s}) appears {:d} times".format(*row), level=3)

    def remove_duplicates(self):
        """Delete all duplicate files from the database; case sensitive"""
        # select any record with an id less than its maximum, and delete it
        self.c.execute("DELETE FROM hashes WHERE id NOT IN (SELECT MAX(id) AS maxid FROM hashes GROUP BY filename, md5);")
        # check that there are no duplicates?
        self.commit() # should we?


class HashGrabber(object):
    def __init__(self, db_fn="hashes.sqb", delete=False):
        self.db = Database(fn=db_fn)
        self.reinitialize(delete=delete)

    def close(self):
        """Convenience accessor"""
        self.db.close()

    def reinitialize(self, delete=True):
        """Delete the database contents, probably"""
        self.db.initialize(delete=delete)

    def check_one_file(self, fn, skip_weird=True):
        """Compute the hash of a single file"""
        h = hashlib.md5()
        rfn = os.path.basename(fn) # filename w/o path, for db
        # compressed data -- needs decompression
        if fn.casefold().endswith(os.path.extsep+"uz2"):
            rfn = os.path.basename(fn[:-4]) # fn.rpartition(os.path.extsep)[0]
            log("{:s} appears to be a compressed file".format(fn), level=4)
            # decompress file, feed directly into md5 computation
            chunks = 0 # debugging tool!
            fs = os.path.getsize(fn) # known compressed filesize
            size = 0 # measured decompressed filesize
            with open(fn, 'rb') as f:
                while fs > 0: # we could also while True:
                    try: cs, us = struct.unpack("<II", f.read(8))
                    except struct.error: # we're at EOF expectedly
                        log("Expected EOF in `{:s}` at chunk index {:d}"\
                            .format(fn, chunks), level=4)
                        break
                    # Input validation
                    if cs > 33096:
                        log("{:s} chunk {:d} reports oversize compressed size"\
                            .format(fn, cs), level=2)
                    elif us > 32768:
                        log("{:s} chunk {:d} reports oversize uncompressed \
size".format(fn, us), level=2)
                    elif cs == 0:
                        log("{:s} chunk {:d} reports zero compressed size"\
                            .format(fn, cs), level=1)
                        # the code will probably crash, might need to handle
                    elif us == 0:
                        log("{:s} chunk {:d} reports zero uncompressed size"\
                            .format(fn, us), level=1)
                        # the code will probably crash, might need to handle
                    chunk = f.read(cs)
                    fs -= 8+cs # if this is negative, something is wrong
                    if len(chunk) != cs: # we're at EOF unexpectedly
                        log("Unexpected EOF in `{:s}` chunk index {:d}"\
                            .format(fn, chunks), level=1)
                        return (rfn, None, None) # break
                    # following debug output is noisy -- mute it
##                    log("Decompress chunk index {:d}: cs={:d} us={:d}"\
##                        .format(chunks, cs, us), level=4)
                    chunk = zlib.decompress(chunk, 15, us)
                    size += us #len(chunk)
                    h.update(chunk)
                    chunks += 1
            # exit point for compressed data
            return (rfn, size, h.hexdigest())
        # uncompressed data of known type
        elif any(map(lambda q:fn.casefold().endswith(q),
                     ("u", "ucl", #"est", "frt", "int", "itt", "kot", "det",
                      "ukx", "uxx", "ka", "ut2", "ogg", "uax", "usx", "utx"))):
            if fn.casefold().endswith("uxx"):
                log("{:s} is a cache file!", level=2)
        else:
            log("Filetype ({:s}) of file {} is weird!"\
                .format(fn.rpartition(os.path.extsep)[2], fn), level=4)
            if skip_weird: return (rfn, None, None)
        size = os.path.getsize(fn)
        if size > 2147483647:
            log("{:s} is a huge (>2GB) file!", level=1)
            return (rfn, None, None)
        # read the file out in little chunks
        with open(fn, 'rb') as f:
            while True:
                chunk = f.read(32768)
                if not chunk: break
                h.update(chunk)
        return (rfn, size, h.hexdigest())
            
    def scan_directory(self, fp):
        """Load hashes *into database* for all files in a folder"""
        # scandir is new in 3.5, i don't have that
        for fn in os.listdir(fp): # fn contains path relative to fp
            p = os.path.join(fp, fn) # get reasonably full path
            if not os.path.isfile(p):
                log("Skipping {}: is a folder".format(fp), level=4)
                continue
            try: rfn, size, md5 = self.check_one_file(p)
            except:
                # This is not a very intelligent error handler
                log("Got some kind of error parsing {:s}".format(rfn), level=1)
                md5 = None # force next step to fail
            if md5 is None:
                log("Got no hash for {:s}, probably not a valid file"\
                    .format(fn), level=4)
                continue
            log("rfn={:s} size={:d} md5={:s}".format(rfn, size, md5), level=4)
            self.db.put(rfn, size, md5)
        self.db.commit()

    def scan_game(self, fp):
        """Load hashes *into database* using a UT2004 game folder"""
        for gp in ("Animations", "KarmaData", "Maps", "Music", "Sounds",
                   "System", "Textures"):
            if os.path.isdir(os.path.join(fp, gp)):
                log("Scanning game directory {}".format(gp), level=3)
                self.scan_directory(os.path.join(fp, gp))
            else:
                log("Game directory {} does not exist or is not a directory!"\
                    .format(gp), level=2)


class UserInterface(object):
    """Base class for high-level operations/automation"""
    # we will decide later on whether a CLI user interface is presented or
    # whether we just use what's given via argparse, so we accept everything
    # in the constructor.
    def __init__(self, cwd=None, casefold=True, interactive=False,
                 db_fn="hashes.sqb", wipe_on_start=False, build_first=False,
                 using_gamedir=False, search_md5=None, verbosity=3,
                 out=None):
        # cwd -- working directory for building the database.
        # casefold -- whether filenames are forced lowercase when building.
        #              Rebuild database if changed.
        # db_fn -- filename of database to use.
        # wipe_on_start: whether the db should be wiped before doing anything.
        # build_first: whether the db should be built before searching it.
        # using_gamedir: whether to search UT2004 game folders under cwd
        #                 instead of cwd itself (searches are never recursive).
        # search_md5: if not interactive, the search string to look for.
        # verbosity: how much console output you should receive
        #            (0: fatal | 1: error | 2: warn | 3: info | 4: debug)
        # out: where program output should go. Console always included in
        #      interactive mode. If defined, specify a file. 
        global MIN_LEVEL # we can adjust otherwise hardcoded verbosity here
        if verbosity in (0, 1, 2, 3, 4): MIN_LEVEL = verbosity
        if not cwd: self.cwd = os.path.curdir
        else: self.cwd = cwd
        self.exit_code = 0
        # validate validity of search md5 string, return before altering db
        if search_md5 is not None:
            search_md5 = search_md5.casefold()
            if not all(map(lambda q: q in "abcdef1234567890", search_md5)) and \
               len(search_md5) != 32:
                log("Search MD5 string invalid!", level=0)
                self.exit_code = 1
                return
        self.sm5 = search_md5
        self.casefold = casefold
        if cwd is None: cwd = os.path.curdir
        self.cwd = cwd
        self.interactive = interactive
        if build_first: # poor man's bitmapping
            self.build_opt = (3 if using_gamedir else 1)
        else: self.build_opt = 0
        # handle output file
        if out:
            try: self.of = open(out, "w")
            except OSError as e:
                log("Couldn't open output file! [{:r}]"\
                    .format(e.args), level=0)
                self.exit_code = 1
                return
        # now that we have our vars, create the database object
        self.h = HashGrabber(db_fn=db_fn, delete=wipe_on_start)
        self.h.db.force_casefold = self.casefold
        # transfer control depending on whether we are interactive
        if interactive: self.run()
        else: self.run_passive()
        
    def run_passive(self):
        """Run the command desired and quit. This allows deleting the db!"""
        # db would have been deleted in the constructor, if needed
        # casefold is set up in constructor
        # if we have defined database build options, act on them
        if self.build_opt == 1:
            self.h.scan_directory(self.cwd)
        elif self.build_opt == 3:
            self.h.scan_game(self.cwd)
        if not self.sm5: return
        # determine where output goes
        target = getattr(self, "of", stdout)
        print("filename\tsize\tmd5", file=target)
        for row in self.db.find(self.sm5):
            print(*row, sep='\t', file=target)
        print(end='', file=target, flush=True) # force a flush(?)

    def run(self):
        """Run an interactive command interface, useful for testing/debugging"""
        log("UT2Hash v{:X}.{:02X} by CVSoft"\
            .format(VERSION >> 8, VERSION & 0xFF), level=-3)
        while True:
            try: rcmd = input("CMD > ")
            except KeyboardInterrupt:
                log("Exiting due to KeyboardInterrupt", level=-3)
                break
            cmd, _, arg = rcmd.partition(' ')
            # hardcode the exit command to get out of the loop
            if cmd == "exit" or cmd == "quit" or cmd == "q": break
            # offload actual commands to individual methods for flexibility
            if hasattr(self, "cmd_"+cmd):
                try: getattr(self, "cmd_"+cmd)(arg)
                except:
                    log("Command {:s} encountered an exception. Info follows:"\
                        .format(cmd), level=-2)
                    traceback.print_exception(*exc_info())
            print(flush=True)

    def cmd_help(self, arg):
        """Show command help"""
        if arg.casefold() == "set":
            log("SET commands:", level=-3)
            log(" verbosity: Sets verbosity. 4 is highest, 0 is lowest.",
                level=-3)
            log(" folder: Sets scan folder to current (cwd), UT2004 install \
(game), or none.", level=-3)
            log(" cwd: Sets what folder will be scanned for files.", level=-3)
            log(" db: Sets the filename of the database. The currently open \
database will", level=-3)
            log("      be committed and closed, and the new database opened.")
            log(" casefold: Set to true to force new filename entries to be \
lowercase.", level=-3)
            log("            Wipe the database and build after changing this.",
                level=-3)
            log(" target: Set command output to console or a file.", level=-3)
            return
        log("Commands:", level=-3)
        log(" exit / quit / q: Exit the program and commit the database.",
            level=-3)
        log(" help: Show command help.", level=-3)
        log(" wipe: Erase database contents.", level=-3)
        log(" build: Create database contents using contents of CWD.")
        log(" commit: Commit any recent changes to the database.", level=-3)
        log(" revert: Revert any recent changes to the database.", level=-3)
        log(" find: Search the database for a MD5 hash.", level=-3)
        log(" name: Search the database for a filename.", level=-3)
        log(" hash: Compute the hash of a single file relative to CWD.",
            level=-3)
        log(" count: Show number of rows in the database.", level=-3)
        log(" dump: Print every row in the database. Not wise!", level=-3)
        log(" dupe: Eliminate duplicate rows, case-sensitive.", level=-3)
        log(" set : Set program parameters. See `help set`.", level=-3)
        log(" get : Get program parameters. See `help set`.", level=-3)

    def cmd_hash(self, arg):
        """Compute the hash of a single file relative to cwd"""
        fp = os.path.join(self.cwd, arg)
        if not os.path.isfile(fp):
            log("Requested file `{:s}` does not exist or is not a file."\
                .format(fp), level=-2)
            return
        target = getattr(self, "of", stdout)
        print("filename\tsize\tmd5", file=target)
        row = self.h.check_one_file(fp, skip_weird=False)
        print(*row, sep='\t', file=target)
        print(end='', file=target, flush=True)

    def cmd_find(self, arg):
        """Search the database for a MD5 hash"""
        self.sm5 = arg.lower()
        # borrow some code
        if not all(map(lambda q: q in "abcdef1234567890", self.sm5)) and \
           len(self.sm5) != 32:
            log("Search MD5 string invalid!", level=-2)
            return
        target = getattr(self, "of", stdout)
        print("filename\tsize\tmd5", file=target)
        for row in self.h.db.find(self.sm5):
            print(*row, sep='\t', file=target)
        print(end='', file=target, flush=True)

    def cmd_name(self, arg):
        """Search the database for a filename"""
        # aside from what Python does, this input is otherwise unsanitized!
        if ';' in arg or ':' in arg or ' ' in arg:
            log("Search filename string invalid!", level=-2)
            return
        target = getattr(self, "of", stdout)
        print("filename\tsize\tmd5", file=target)
        for row in self.h.db.find_by_name(arg):
            print(*row, sep='\t', file=target)
        print(end='', file=target, flush=True)

    def cmd_count(self, arg):
        """Show number of rows in the database"""
        target = getattr(self, "of", stdout)
        print("rows", file=target)
        print(self.h.db.count_rows(), file=target)
        print(end='', file=target, flush=True)

    def cmd_dump(self, arg):
        """Dump every row of the database to desired output"""
        target = getattr(self, "of", stdout)
        print("filename\tsize\tmd5", file=target)
        for row in self.h.db.dump(raw=True):
            print(*row, sep='\t', file=target)
        print(end='', file=target, flush=True)

    def cmd_dupe(self, arg):
        """Eliminate duplicate rows"""
        self.h.db.remove_duplicates()
        log("Duplicate rows have been removed.", level=-3)

    def cmd_hdupe(self, arg):
        """Find duplicate hashes, kinda incomplete"""
        if MIN_LEVEL < 3:
            log("Your verbosity is too low to see output! \
Set it to 3 or higher.", level=-2)
        self.h.db.find_duplicate_hashes()

    def cmd_wipe(self, arg):
        """Wipe the database's table"""
        log("You're about to wipe the database!", level=-2)
        rcmd = input("!!!!! Are you sure? (Y/n) > ")
        if rcmd == 'Y':
            self.h.reinitialize(delete=True)
            log("Database reinitialized.", level=-3)
        else: log("Operation aborted.", level=-3)

    def cmd_build(self, arg):
        bmo = self.build_opt
        arg = arg.casefold()
        # determine if there is an override, if building is enabled
        if self.build_opt > 0:
            if arg == "game": bmo = 3
            elif arg == "cwd": bmo = 1
        elif arg in ("game", "cwd") and self.build_opt == 0:
            log("Set folder to something other than none to use overrides!",
                level=-2)
        if bmo == 0:
            log("Cannot build database: folder mode is set to none.", level=-2)
            return
        log("Build commencing...", level=-3)
        if bmo == 1:
            self.h.scan_directory(self.cwd)
        elif bmo == 3:
            self.h.scan_game(self.cwd)
        log("Build completed.", level=-3)

    def cmd_commit(self, arg):
        """Forcibly commit changes to the database"""
        self.h.db.commit()
        log("Any recent changes to the database have been committed.", level=-3)

    def cmd_revert(self, arg):
        """Forcibly revert changes to the database"""
        self.h.db.conn.revert()
        log("Any recent changes to the database have been reverted.", level=-3)

    def cmd_set(self, arg):
        key, _, arg = arg.partition(' ')
        key = key.casefold()
        if key and not arg:
            log("Not enough parameters for SET.", level=-2)
            return
        elif not key or not arg:
            log("Invalid set parameters", level=-2)
            return
        if key == "verbosity":
            if arg not in ("0", "1", "2", "3", "4"):
                log("Unrecognized value for verbosity. Valid: 0, 1, 2, 3, 4.",
                    level=-2)
                return
            global MIN_LEVEL
            MIN_LEVEL = int(arg)
        elif key == "folder":
            if arg not in ("none", "cwd", "game"):
                log("Unrecognized value for folder. Valid: none, cwd, game.")
                return
            if arg == "game":
                self.build_opt = 3
                log("Set folder to UT2004 installation.", level=-3)
            elif arg == "cwd":
                self.build_opt = 1
                log("Set folder to current working directory.", level=-3)
            else:
                self.build_opt = 0
                log("Database building has been disabled.", level=-2)
        elif key == "cwd":
            if not os.path.isdir(arg):
                log("Cannot access desired CWD, or it is not a directory.",
                    level=-2)
                return
            self.cwd = arg
            log("CWD set to `{:s}`.".format(self.cwd), level=-3)
        elif key == "force_cwd":
            self.cwd = arg
            log("Forcing CWD to `{:s}`.".format(self.cwd), level=-2)
        elif key == "db":
            log("This will close the current database.", level=-2)
            rcmd = input("!!!!! Are you sure? (Y/n) > ")
            if rcmd == 'Y':
                self.h.db.close()
                self.h.db = Database(fn=arg)
                self.h.reinitialize(delete=False)
                log("New database `{:s}` opened.".format(arg), level=-3)
        elif key == "casefold":
            if arg not in ("true", "false"):
                log("Unrecognized value for casefold. Valid: true, false.",
                    level=-2)
                return
            is_casefold_new = (self.casefold != (arg == "true"))
            self.casefold = (arg == "true")
            self.h.db.casefold = self.casefold
            if is_casefold_new:
                log("Casefold setting updated. Wipe and build database for \
this to take effect.", level=-3)
        elif key == "target":
            if arg == "console":
                del self.of
                log("Output target set to console.", level=-3)
            else:
                self.of = arg
                log("Output target set to file `{:s}`.".format(self.of),
                    level=-3)
                log("Set target to `console` to reset output to console.",
                    level=-3)
        else:
            log("Unrecognized keyword `{:s}`.".format(key), level=-2)

    def cmd_get(self, arg):
        """View configuration parameters"""
        arg = arg.casefold()
        if arg == "verbosity":
            log("Verbosity: {:d} ({:s})"\
                .format(MIN_LEVEL, ("Fatal", "Error", "Warning",
                                    "Informational", "Debug")[MIN_LEVEL]),
                level=-3)
        elif arg == "folder":
            log("Folder target: {:s}"\
                .format(("game" if self.build_opt == 3 else "cwd")), level=-3)
        elif arg == "cwd":
            log("Current working directory: `{:s}`".format(self.cwd), level=-3)
        elif arg == "db":
            log("Current database: `{:s}`".format(h.db.fn), level=-3)
        elif arg == "casefold":
            log("Casefold: {:s} (by DB) / {:s} (by program)"\
                .format(("true" if h.db.force_casefold else "false"),
                        ("true" if self.casefold else "false")), level=-3)
        elif arg == "target":
            log("Output target: {:s}"\
                .format(getattr(self, of, "console")), level=-3)
        else:
            log("Unrecognized keyword `{:s}`.".format(arg, level=-2))
            
        
def main():
    """Wrapper for argparse"""
    p = argparse.ArgumentParser(description="Store MD5 hashes of decompressed \
UZ2 files, or other UT2004 files, in a database.")
    p.add_argument("-i", "--interactive", dest="interactive", type=bool,
                   default=False, help="Launch an interactive shell instead of \
running a single query.")
    p.add_argument("--casefold", dest="casefold", type=bool, default=True,
                   help="Force filenames lowercase during database build.")
    p.add_argument("--cwd", dest="cwd", help="Define a file search directory.")
    p.add_argument("--db", dest="dbfn", default="hashes.sqb",
                   help="Filename of the SQLite database. Default `hashes.sqb`")
    p.add_argument("--wipe-on-start", dest="wipe", type=bool, default=False,
                   help="Erase the database contents immediately upon opening.")
    p.add_argument("--build", dest="build_first", type=bool, default=False,
                   help="Build the database before searching it.")
    p.add_argument("--use-game-dir", dest="use_gamedir", type=bool,
                   default=False,
                   help="Search UT2004 folder structure instead of CWD.")
    p.add_argument("--md5", "-m", dest="md5", type=str, default=None,
                   help="MD5 hash to search the database for.")
    p.add_argument("--verbosity", "-v", dest="verbosity", type=int,
                   choices=(0, 1, 2, 3, 4), default=3, 
                   help="Sets the amount of program output -- lower is less.")
    p.add_argument("--out", "-o", dest="out", type=str, default=None,
                   help="(Optional) Redirect query outputs to a file.")
    a = p.parse_args()
    # always run interactive from IDLE
    i = ("idlelib.run" in modules and __name__ == "__main__") or \
        a.interactive
    u = UserInterface(cwd=a.cwd, casefold=a.casefold, interactive=i,
                      db_fn=a.dbfn, wipe_on_start=a.wipe,
                      build_first=a.build_first, using_gamedir=a.use_gamedir,
                      search_md5=a.md5, verbosity=a.verbosity, out=a.out)
    return u.exit_code


# if running directly in IDLE, run main()
if "idlelib.run" in modules and __name__ == "__main__":
    main()
