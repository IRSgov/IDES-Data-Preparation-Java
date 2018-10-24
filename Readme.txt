** MAKE SURE YOU HAVE UNLIMITED JCE JARS, local_policy.jar AND US_export_policy.jar, IN JRE/LIB/SECURITY FOLDER
** SET JAVA_HOME in run.bat

Create FATCADataPrepTool.jar command - assuming 'bin' is compiled files root folder:
jar vcmf FATCA.MF FATCADataPrepTool.jar -C bin fatca -C bin impl -C bin intf -C bin util log4j.xml

Execute commands:
java -Dfile.encoding=UTF8 -jar FATCADataPrepTool.jar <ConfigAndCmds file - default ConfigAndCmds.txt>

Configurations and commands syntax in ConfigAndCmds.txt:
senderPrivateKSType=<jks|pkcs>
senderPublicKSType=<jks|pkcs>
receiverPrivateKSType=<jks|pkcs>
receiverPublicKSType=<jks|pkcs>
approverPrivateKSType=<jks|pkcs>
approverPublicKSType=<jks|pkcs>

senderPrivateKSFile=<sender private keystore file>
senderPublicKSFile=<sender public keystore file>
receiverPrivateKSFile=<receiver private keystore file>
receiverPublicKSFile=<receiver public keystore file>
approverPrivateKSFile=<approver private keystore file>
approverPublicKSFile=<approver public keystore file>

senderPrivateKSPwd=<sender private keystore password>
senderPublicKSPwd=<sender public keystore password>
receiverPrivateKSPwd=<receiver private keystore password>
receiverPublicKSPwd=<receiver public keystore password>
approverPrivateKSPwd=<approver private keystore password>
approverPublicKSPwd=<approver public keystore password>

senderPrivateKeyPwd=<sender private key password>
receiverPrivateKeyPwd=<receiver private key password>
approverPrivateKeyPwd=<approver private key password>

senderPrivateKeyAlias=<sender private key alias>
senderPublicKeyAlias=<sender public key alias>
receiverPrivateKeyAlias=<receiver private key alias>
receiverPublicKeyAlias=<receiver public key alias>
approverPrivateKeyAlias=<approver private key alias>
approverPublicKeyAlias=<approver public key alias>

senderGiin=<sender giin>
receiverGiin=<receiver giin - generally USA/IRS giin>
approverGiin=<approver giin - for model1 option2 FFI>
taxYear=<tax year>

receiverPublicCert=<receiver public cert - generally USA/IRS. If present then receiverPublicKSType, receiverPublicKSFile, receiverPublicKSPwd and receiverPublicKeyAlias not required>

//comment line

/* 
block comment lines
*/
//output from a command is default input to next command

//signature reference object id tag - default Object
sigRefIdPos=<Object|SignatureProperty|SignatureProperties>

//signature transformation - default Inclusive
sigXmlTransform=<Inclusive|Exclusive 

//apply only for signAndCreatePkg command set. If true, signed xml file will not be deleted
keepSignedXmlAfterSignAndCreatePkgFlag=<true|false - default false>

//verifyAllSignature xml signatures for all commands that involve signature
verifyAllSignature=<true|false> 

//setMetadata email, fileRevisionId and origTransId
//usage: setMetadataInfo email=<email> [fileRevisionId=true|false] [origTransId=<origTransId>]
setMetadataInfo email=<email>
setMetadataInfo email=<email> fileRevisionId=false
setMetadataInfo email=<email> fileRevisionId=true|false origTransId=<origTransId>

//for large file use 'Streaming' based cmds

//sign and create ides package - use streaming based cmd for large file
//usage: signAndCreatePkgStreaming [input=<xml>] [fatcaEntCommCd=NTF|RPT|CAR|REG - default RPT]
signAndCreatePkgStreaming input=<unsigned xml>
//usage: signAndCreatePkg [input=<xml>] [fatcaEntCommCd=NTF|RPT|CAR|REG - default RPT]
signAndCreatePkg input=<unsigned xml>

//usage: signAndCreatePkgWithApproverStreaming [input=<xml>] [fatcaEntCommCd=NTF|RPT|CAR|REG - default RPT]
signAndCreatePkgWithApproverStreaming input=<unsigned xml>
//usage: signAndCreatePkgWithApprover [input=<xml>] [fatcaEntCommCd=NTF|RPT|CAR|REG - default RPT]
signAndCreatePkgWithApprover input=<unsigned xml>

//usage: signBinaryAndCreatePkgStreaming [input=<binary>] [fileFormat=PDF|RTF|JPG] [fatcaEntCommCd=NTF|RPT|CAR|REG - default RPT]
signBinaryAndCreatePkgStreaming input=<binary file> fileFormat=<PDF|JPG|RTF>
//usage: signBinaryAndCreatePkgStreaming [input=<binary>] [fileFormat=PDF|RTF|JPG] [fatcaEntCommCd=NTF|RPT|CAR|REG - default RPT]
signBinaryAndCreatePkg input=<binary file> fileFormat=<PDF|JPG|RTF>

//usage: signTextAndCreatePkgStreaming [input=<txt>] [fatcaEntCommCd=NTF|RPT|CAR|REG - default RPT]
signTextAndCreatePkgStreaming input=<text file>
//usage: signTextAndCreatePkg [input=<txt>] [fatcaEntCommCd=NTF|RPT|CAR|REG - default RPT]
signTextAndCreatePkg input=<text file>

//sign a file - use streaming based cmd for large file
signXmlStreaming input=<file to sign> output=<output signed file> sigKey=senderPrivateKey sigPublicCert=senderPublicCert
signXml input=<file to sign> output=<output signed file> sigKey=senderPrivateKey sigPublicCert=senderPublicCert

//verifySignature - for large file use 'Streaming' based cmds
//usage: verifySignature[input=<signed xml>] [sigPublicCert=senderPublicCert]
verifySignature input=<signed file>

//usage: verifySignatureStreaming [input=<signed xml>] [sigPublicCert=senderPublicCert]
verifySignatureStreaming input=<signed file>

//wraps text in xml and sign - use streaming based cmd for large file
wrapTextInXmlAndSignStreaming input=<text file to sign> output=<signed text file output> sigKey=senderPrivateKey sigPublicCert=senderPublicCert
wrapTextInXmlAndSign input=<text file to sign> output=<signed text file output> sigKey=senderPrivateKey sigPublicCert=senderPublicCert

//wraps PDF|JPG|RTF etc binary file in xml and sign - use streaming based cmd for large file
wrapBinaryInXmlAndSignStreaming input=<binary file to sign> output=<signed binary file output> sigKey=senderPrivateKey sigPublicCert=senderPublicCert
wrapBinaryInXmlAndSign input=<binary file to sign> output=<signed binary file output> sigKey=senderPrivateKey sigPublicCert=senderPublicCert

createBinaryFromSignedBase64Binary input=<signed wrapped base64 encoded binary> output=<binary output>

//create package from signed xml
//usage: createPkg [input=<signed xml>] [fileFormatCd=XML|TXT|PDF|JPG|RTF - default XML] [binaryEncodingSchemeCd=NONE|BASE64 - default NONE] [fatcaEntCommCd=NTF|RPT|CAR|REG - default RPT]
createPkg input=<signed xml> fileFormatCd=XML binaryEncodingSchemeCd=NONE fatcaEntCommCd=RPT
createPkgWithApprover input=<signed xml>

//unpack ides pkg - with receiver private key
unpack input=<ides package>

//unpack ides pkg - with approver private key
unpackForApprover input=<ides package>

//stops JVM
stop
