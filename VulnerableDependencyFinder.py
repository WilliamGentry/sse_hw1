import os
import requests
from zipfile import ZipFile
import sqlite3
from sqlite3 import Error
import sys
import xml.dom.minidom

# Hardcoded paths
data_folder = './NVD_DATA'
resource_url = 'https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip'
data_file_zip_path = data_folder + '/nvdcpmatch.json.zip'
data_file = data_folder + '/nvdcpematch-1.0.json'
db_dir = './db'
db_file = db_dir + "/cpematches.db"
report_file_path = "./report.txt"

# SQL Queries
insert_sql = """INSERT INTO vulnerabilities (name, major, minor, patch) VALUES (?, ?, ?, ?)"""
create_sql = """CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY,
            name CHARACTER(255) NOT NULL,
            major CHARACTER(8),
            minor CHARACTER(8),
            patch CHARACTER(8)
        )"""
check_sql = """SELECT * FROM vulnerabilities LIMIT 1"""
vuln_sql = """SELECT * FROM vulnerabilities WHERE name = (?)"""


def create_connection(db_file):
    """ Create a database connection to SQLite database """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Error as e:
        print("Error connected to database")
        print(e)
        sys.exit(1)
    finally:
        if conn:
            return conn
        sys.exit(1)


# Fetch data, create directories etc as necessary
if not os.path.exists(data_folder):
    os.makedirs(data_folder)

if not os.path.exists(data_file):
    print("Requesting data from NIST...")
    r = requests.get(resource_url, allow_redirects=True)

    print("Writing data to file...")
    open(data_file_zip_path, 'wb').write(r.content)

    print("Unzipping...")
    with ZipFile(data_file_zip_path, 'r') as zipObj:
        zipObj.extractall(data_folder)


if not os.path.exists(db_dir):
    print("Making directory for database...")
    os.makedirs(db_dir)

# Connect to db
conn = create_connection(db_file)

# Create table
conn.execute(create_sql)

# Check if table empty, if not populate from file
c = conn.cursor()
checkDB = c.execute(check_sql)
if len(checkDB.fetchall()) == 0:
    print("Populating database with vulnerability information...")
    f = open(data_file, 'r')
    for line in f:
        if line.startswith('      "cpe23Uri"'):
            sections = line.split(':')
            name = sections[5]
            versionNumList = sections[6].split('.')
            try:
                if versionNumList[0].isdigit():
                    major = versionNumList[0]
                else:
                    major = "NULL"
            except:
                major = "NULL"
            try:
                if versionNumList[1].isdigit():
                    minor = versionNumList[1]
                else:
                    minor = "NULL"
            except:
                minor = "NULL"
            try:
                if versionNumList[2].isdigit():
                    patch = versionNumList[2]
                else:
                    patch = 'NULL'
            except:
                patch = "NULL"

            c = conn.cursor()
            c.execute(insert_sql, (name, major, minor, patch))
    f.close()
    conn.commit()

# Open and parse pom file
try:
    pom = xml.dom.minidom.parse(sys.argv[1])
except:
    print("Error: Please pass a valid pom.xml file path")
    sys.exit(1)

# Extract dependency ids and versions
dependDict = {}
dependencies = pom.getElementsByTagName("dependency")
for dependency in dependencies:
    artifactId = dependency.getElementsByTagName(
        "artifactId")[0].childNodes[0].data
    version = dependency.getElementsByTagName("version")[0].childNodes[0].data
    dependDict[artifactId] = version

# Go through dependDict, query db by dependency name and version, print out warnings
vulnerabilities_detected = False
report = ""
for name, version in dependDict.items():
    major = version.split('.')[0]
    try:
        minor = version.split('.')[1]
    except:
        minor = '0'
    try:
        patch = version.split('.')[2]
    except:
        patch = '0'
    c = conn.cursor()
    matching_vulns = c.execute(vuln_sql, (name,)).fetchall()
    if matching_vulns:
        for result in matching_vulns:
            if result[2] == major or result[2] == 'NULL':
                if result[3] == minor or result[3] == 'NULL':
                    if result[4] == patch or result[4] == 'NULL':
                        report += "Vulnerability: " + name + " " + version + '\n'
                        print("Vulnerability: " + name + " " + version)
                        vulnerabilities_detected = True
                        break
if not vulnerabilities_detected:
    report = "No vulnerabilities detected!"
    print("No vulnerabilities detected!")

report_file = open(report_file_path, 'w')
report_file.write(report)
report_file.close()
conn.close()
