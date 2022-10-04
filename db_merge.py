#!/usr/bin/env python3

import argparse
import sqlite3
import shutil

def arguments():
	ap = argparse.ArgumentParser()
	ap.add_argument('infiles', type=str, nargs='+')
	ap.add_argument('outfile', type=str)
	ap.add_argument('--quiet', action='store_true')
	return ap.parse_args()


def main():
	args = arguments()

	shutil.copy(args.infiles[0], args.outfile)

	with sqlite3.connect(args.outfile) as db:
		db.execute('PRAGMA journal_mode = OFF;') # remove if relying on unique constraints to roll back inserts
		db.execute('PRAGMA synchronous = 0;') # could corrupt if power lost
		db.execute('PRAGMA cache_size = 1000000;')
		db.execute('PRAGMA locking_mode = EXCLUSIVE;')
		db.execute('PRAGMA temp_store = MEMORY;')

		tables = [str(row[1]) for row in db.execute("SELECT * FROM sqlite_master WHERE type='table'")]
		print(tables)

		for fn in args.infiles[1:]:
			print(fn)
			db.execute("ATTACH '" + fn + "' as dba")
			db.execute("BEGIN")

			for table in tables:
				db.execute("INSERT OR IGNORE INTO " + table + " SELECT * FROM dba." + table)

			db.commit()
			db.execute("DETACH DATABASE dba")


if __name__ == '__main__':
	main()
