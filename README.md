#Discord Parser

Discord paser is a third party module for autopsy which extracts artifacts from Discord Windows application.

#Installation

Download the .py file and create a new folder in the given path and paste it in the folder: C:\Users\[Username]\AppData\Roaming\autopsy\python_modules

#Usage

Take individual raw files in cache folder of discord as logical file set in autopsy.

Discord cache files are located in the following folder: C:\Users\[Username]\AppData\Roaming\discord\Cache

To run the ingest module in autopsy, click on tools in menubar and select run ingest module. Select Discord Desktop App Analyzer in the ingest modules.

The results will be shown in Extracted Contents as "Discord Cache".

#Working

The module take raw files starting with "data" in Discord cache as input. In these raw files there are multiple gzip formatted files stored. The module finds those files and unzips them.

The data stored in those GZIP files are in JSON format. So after unzipping them, the module then finds relevant data in the JSON like messages, username, discriminator, timestamps etc and displays those artifacts in autopsy as "Discord cache".

