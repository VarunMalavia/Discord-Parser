import gzip 
import zlib
import json
import struct
from io import BytesIO
import os
import sys
import string
import re
from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.util import ArrayList
from java.io import File
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class DiscordParseIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "Discord Desktop App Analyzer"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Module That Parses Discord cache file"

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return DiscordParseIngestModule()


# Data Source-level ingest module.  One gets created per data source.
class DiscordParseIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(DiscordParseIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None
        
    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

    def create_artifact_type(self,case,art_Name,desc):
        try:
            artId = case.addArtifactType(art_Name, desc)
            return case.getArtifactTypeID(art_Name)
        except:
            return case.getArtifactTypeID(art_Name)


    def create_attribute_type(self, case, att_type, description):
        try:
            message = "Creating Attribute: " + att_type
            #self.log(Level.INFO, message)
            result = case.addArtifactAttributeType(att_type,
                    BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, description)
        except:
            message = "Attribute Exists: " + att_type
            #self.log(Level.INFO, message)
        return case.getAttributeType(att_type)

    def add_artifact(self,art_file,attID,att_content):
        art_file.addAttribute(BlackboardAttribute(attID, DiscordParseIngestModuleFactory.moduleName, att_content))

    def gzip_Find(self,file):
        #message2 = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Discord Analyzer", "%d" % len(file))
        #IngestServices.getInstance().postMessage(message2)
        artifact = []
        with open(file,"rb") as a:
            b = a.read()
            
            a.seek(0,0)
            
            
            for match in re.finditer('\x1f\x8b',b):
                a.seek(match.start(),0)
                #message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Discord Analyzer", "%d" % a.tell())

                #IngestServices.getInstance().postMessage(message)
                
                
                a.seek(10,1)
                j=0          
                
                while j==0:
                    c = a.read(1)
                    if c == b'\x00':
                        if a.read(2) == b'\x00\x00':
                            if a.read(3)==b'\x00\x00\x00' :
                                a.seek(-8,1)
                                

                                size =  struct.unpack('<i',a.read(4))[0]
                                j=1
                            else:
                                a.seek(-3,1)
                                                                
                a.seek(match.start(),0)
                compressed = a.read(size)
                inbuffer = BytesIO(compressed)
                try:
                    with gzip.GzipFile(mode='rb',fileobj=inbuffer) as g:
                        read_data = g.read(int(size))
                    
                except:
                    continue

                try:
                    parsed = json.loads(read_data)
                    try:
                        for i in parsed:
                            username = i['author']['username'].encode('utf-8')
                            ID = i['author']['id'].encode('utf-8')
                            discriminator = i['author']['discriminator'].encode('utf-8')
                            timestamp = i['timestamp'].encode('utf-8')
                            message = i['content'].encode('utf-8')
                            channel_ID = i['channel_id'].encode('utf-8')
                            artifact.append(username)
                            artifact.append(ID)
                            artifact.append(discriminator)
                            artifact.append(timestamp)
                            artifact.append(message)
                            artifact.append(channel_ID)
                            
                            #message1 = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Discord Analyzer", "%s"%username)
                            #IngestServices.getInstance().postMessage(message1)
                        #message1 = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Discord Analyzer", "%s"%ID)
                        #IngestServices.getInstance().postMessage(message1)
                        #message1 = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Discord Analyzer", "%s"%discriminator)
                        #IngestServices.getInstance().postMessage(message1)
                        #message1 = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Discord Analyzer", "%s"%timestamp)
                        #IngestServices.getInstance().postMessage(message1)
                            #message1 = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Discord Analyzer", "%s"%message)
                            #IngestServices.getInstance().postMessage(message1)
                        #message1 = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Discord Analyzer", "%s"%channel_ID)
                        #IngestServices.getInstance().postMessage(message1)
                    
                            
                    except:
                        continue
                except:
                    #message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Discord Analyzer", "In Except")

                    #IngestServices.getInstance().postMessage(message)
        
                    continue
        return artifact
        

    def process(self,dataSource,progressBar):
        #setting up case
        case = Case.getCurrentCase().getSleuthkitCase()
        temporaryDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(), "Discord_Parse")
        try:
            os.mkdir(temporaryDirectory)
        except:
            pass

        #setup artiact and attributes
        artID = self.create_artifact_type(case,"TSK_Discord","Discord cache")
        attID_username = self.create_attribute_type(case, "TSK_Discord_Username", "Username")
        attID_id = self.create_attribute_type(case, "TSK_Discord_ID", "Discord ID")
        attID_disc = self.create_attribute_type(case, "TSK_Discord_Discriminator", "Discriminator")
        attID_timestamp = self.create_attribute_type(case, "TSK_Discord_Timestamp", "Timestamp")
        attID_message = self.create_attribute_type(case, "TSK_Discord_Message", "Message")
        attID_channel_id = self.create_attribute_type(case, "TSK_Discord_Channel_ID", "Channel_ID")

        filecount = 0
        #start processing files:
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "data%")

        for file in files:
            log_file = os.path.join(temporaryDirectory, file.getName())
            
            
            
            ContentUtils.writeToFile(file,File(log_file))
            

            temp2 = os.path.join(temporaryDirectory,"temp2")

            
            with open((log_file),'rb') as f:
                data =  f.read()

            
            with open(temp2,'wb') as f:
                for i in data:
                    f.write(i)
            foo = os.stat(temp2)
            foo = foo.st_size
                
            #message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Discord Analyzer", "%d" % len(data))

            #IngestServices.getInstance().postMessage(message)

            #message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Discord Analyzer", "%d" % foo)

            #IngestServices.getInstance().postMessage(message)
        
            
                
            variable = ()
            
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Discord Analyzer", "%d" % len(variable))

            IngestServices.getInstance().postMessage(message)
           
            variable = self.gzip_Find(log_file)
                
            i = len(variable)
            j=0
            while j<i:
                art = file.newArtifact(artID)
            
                self.add_artifact(art, attID_username, variable[j])
        
                self.add_artifact(art, attID_id, variable[j+1])
                self.add_artifact(art, attID_disc, variable[j+2])
                self.add_artifact(art, attID_timestamp, variable[j+3])
                self.add_artifact(art, attID_message, variable[j+4])
                self.add_artifact(art, attID_channel_id, variable[j+5])
                j+=6
                
            
            filecount+=1
            
               
               
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Discord Analyzer", "Found %d files" % filecount)

        IngestServices.getInstance().postMessage(message)
        return IngestModule.ProcessResult.OK
               
