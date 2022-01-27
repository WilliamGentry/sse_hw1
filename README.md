Vulnerable Dependency Finder
======

Installing and Running 
------
**1. Download files**

Should include the following:
* VulnerableDependencyFinder.py
* requirements.txt
* venv (directory)

**2. Set up virtual environment**
* `source venv/bin/activate`
* `pip install -r requirements.txt`

**3. Run program**
* `python3 VulnerableDependencyFinder.py [file_path]`


Design Decisions
------
I decided to obtain vulnerability data from the CPE Match feed, since this file seemed to have all the information needed in a single place.

For ease of use, I make the program handle installing and unzipping the CPE Match file. It first checks to see whether the files exist already, to avoid unnecessary downloads. One future improvement would be using the metadata hash to determine whether the CPE Match data had been updated since last download, and if so replace existing data with the newer data.

The program then finds particular cpe23Uri lines of the JSON file that correspond to vulnerabilities. These lines contain all the information needed for simple identification, so the program doesn't bother parsing the entire JSON tree. From the cpe23Uri lines, the program extracts the name of the vulnerable package and the version number. The CPE Match data is very complete, and includes a line for each vulnerable version.

This data is then inserted into a local SQLite database. One package might have multiple entries, corresponding to seperate vulnerable versions.

Finally, the pom.xml file is opened and parsed via the Python xml library. Dependencies and their version numbers are extracted and compared against entries in the database. Matches are output on both the command line and in a report.txt file.

One limitation of the program as it currently exists is that the Maven coordinates (artifactId) of a given dependency is often but not always always the name of the dependency in the CPE data. For example, "antlr4-runtime" in pom.xml is a dependency with vulnerable versions, but these are listed in the CPE data as just "runtime". While more sophisticated string matching heuristics could be developed, the simple matching employed by this program works for a wide array of dependencies with listed vulnerabilities.

