

    MEXICO	will "Send"     (ie., SUBMITTER )
    IRS         will "Receive"  (ie., RECIPIENT )



To use this DataPrepTool:


1. Need 64-bit Java SE or JRE or JDK
   AND  Java Cryptography Extension


2. Make sure Java is in your PATH 
     OR otherwise need to include full path to java 
     OR simply put DataPrepTool in java BIN directory


3. Make sure to have two keystore files.
 

4. The 2 keystores in this directory are   KSprivateMX.jks   and   KSpublicMX.jks 
 

5. The KeyStore specifics are:


Keystore    	   KSprivateMX.jks
keystore password: pwd123

	Alias: 	   MEXICOcert
	password:  MEX2014



Keystore:	   KSpublicMX.jks
Keystore Password: pwd123

	Alias:	   MEXICOcert
		   IRScert
 

6.Run the tool with the following line on the command line:

    C:\Program Files\Java\jre8\bin>java -jar data-prep-tool-1.0-SNAPSHOT-shaded.jar

    MEXICO	will "Send"     (ie., SUBMITTER )
    IRS         will "Receive"  (ie., RECIPIENT )


7.  An example xml file exists in the directory as well.
  
    Submitter:   Run the tool with the "send" flow to generate a useable 
                 AES encrypted key and data file from the xml example file.  

    Recipient:   The AES encrypted key and data file can then be used in 
                 the "receive" flow to get the original signed xml as an output.

