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

def merge_databases(db1, db2):
	con3 = sqlite3.connect(db1)

	con3.execute("ATTACH '" + db2 +  "' as dba")

	con3.execute("BEGIN")
	for row in con3.execute("SELECT * FROM dba.sqlite_master WHERE type='table'"):
		combine = "INSERT OR IGNORE INTO "+ row[1] + " SELECT * FROM dba." + row[1]
		print(combine)
		con3.execute(combine)
	con3.commit()
	con3.execute("detach database dba")


def read_files(directory):
	fname = []
	for root,d_names,f_names in os.walk(directory):
		for f in f_names:
			c_name = os.path.join(root, f)
			filename, file_extension = os.path.splitext(c_name)
			if (file_extension == '.sqlitedb'):
				fname.append(c_name)

	return fname

def batch_merge(directory):
	db_files = read_files(directory)
	for db_file in db_files[1:]:
		merge_databases(db_files[0], db_file)



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
