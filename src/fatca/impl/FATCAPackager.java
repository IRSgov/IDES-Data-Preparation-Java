package fatca.impl;

import fatca.intf.IFATCAPackager;
import fatca.senderfilemetadata.BinaryEncodingSchemeCdType;
import fatca.senderfilemetadata.FileFormatCdType;
import impl.Packager;
import intf.IMetadata;

import java.io.File;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

import util.UtilShared;

/*
 * @author	Subir Paul (OS:IT:ES:EST:PA:S1)
 * 
 */
public class FATCAPackager extends Packager implements IFATCAPackager {
	protected IMetadata metadata = null;
	//creates an file following pkg naming convention 
	protected synchronized String getPkgFileName(String folder, String senderGiin) throws Exception {
		logger.debug("--> getPkgFileName(). folder=" + folder + ", senderGiin=" + senderGiin);
		if (!"".equals(folder) && !folder.endsWith("/") && !folder.endsWith("\\"))
			folder += File.separator;
		File file;
		String outfile;
		int attempts = UtilShared.maxAttemptsToCreateNewFile;
		while(true) {
			outfile = folder + sdfFileName.format(new Date(System.currentTimeMillis())) + "_" + senderGiin + ".zip";
			file = new File(outfile);
			if (!file.exists()) {
				if (file.createNewFile() || attempts-- <= 0)
					break;
			}
			Thread.sleep(100);
		}
		if (attempts <= 0)
			throw new Exception ("Unable to getPkgFileName() - file=" + file.getAbsolutePath());
		logger.debug("<-- getPkgFileName()");
		return outfile;
	}
	
	public ArrayList<String> unencryptZipPkg(String pkgFile, PrivateKey privateKey, boolean isApprover) throws Exception {
		return unencryptZipPkg(pkgFile, privateKey, isApprover, true);
	}
	
	//decrypt an pkg
	public ArrayList<String> unencryptZipPkg(String pkgFile, PrivateKey privateKey, boolean isApprover, boolean isRenameZip) throws Exception {
		logger.debug("--> unencryptZipPkg(). pkgFile=" + pkgFile + ", isApprover=" + isApprover);
		boolean ret = false;
		String workingDir = new File(pkgFile).getAbsoluteFile().getParent();
		if (!"".equals(workingDir) && !workingDir.endsWith("/") && !workingDir.endsWith("\\"))
			workingDir += File.separator;
		//unzip zipped pkg in working folder
		ArrayList<String> entryList = unzipFile(pkgFile, workingDir);
		String approverKeyFile=null, receiverKeyFile=null, payloadFile=null, metadataFile=null, filename;
		// get metadata file
		File file;
		String tmp;
		for (int i = 0; i < entryList.size(); i++) {
			filename = entryList.get(i);
			if (filename.contains("Metadata"))
				metadataFile = filename;
			else if (filename.contains("Payload"))
				payloadFile = filename;
			else if (filename.contains("Key")) {
				if (receiverKeyFile == null)
					receiverKeyFile = filename;
				else
					approverKeyFile = filename;
			}
		}
		if (metadataFile == null)
			throw new Exception("Invalid package - no metadata file");
		if (payloadFile == null)
			throw new Exception("Invalid package - no payload file");
	
		HashMap<String, String> map = metadata.getMetadataInfo(metadataFile);
		String receiverId = metadata.getReceiverId(map);
		String senderId = metadata.getSenderId(map);
		if (approverKeyFile != null) {
			if (!receiverKeyFile.contains(receiverId)) {
				filename = approverKeyFile;
				approverKeyFile = receiverKeyFile;
				receiverKeyFile = filename;
			}
		}
		if (receiverId == null || senderId == null || receiverKeyFile == null)
			throw new Exception("Invalid metadata file - missing receiver or sender id OR corrupt zip file - no reveiverKeyFile");
		if (isApprover && approverKeyFile == null)
			throw new Exception("Invalid package - no approverKeyFile");
		String zippedSignedPlainTextFile = UtilShared.getTmpFileName(workingDir, senderId, "Payload.zip");
		//decrypt payload file 
		if (approverKeyFile != null && isApprover)
			ret = decrypt(payloadFile, approverKeyFile, zippedSignedPlainTextFile, privateKey);
		else
			ret = decrypt(payloadFile, receiverKeyFile, zippedSignedPlainTextFile, privateKey);
		file = new File(zippedSignedPlainTextFile);
		if (!ret) {
			if (file.exists()&&!file.delete())file.deleteOnExit();
			zippedSignedPlainTextFile = null;
		} else if (isRenameZip){
			tmp = workingDir + senderId + "_Payload.zip";
			File dest = new File(tmp);
			UtilShared.deleteDestAndRenameFile(file, dest);
			zippedSignedPlainTextFile = tmp;
		}
		if (zippedSignedPlainTextFile != null)
			entryList.add(zippedSignedPlainTextFile);
		entryList.remove(payloadFile);
		file = new File(payloadFile);
		if (file.exists()&&!file.delete())file.deleteOnExit();
		entryList.remove(receiverKeyFile);
		file = new File(receiverKeyFile);
		if (file.exists()&&!file.delete())file.deleteOnExit();
		if (approverKeyFile != null) {
			entryList.remove(approverKeyFile);
			file = new File(approverKeyFile);
			if (file.exists()&&!file.delete())file.deleteOnExit();
		}
		logger.debug("<-- unencryptZipPkg()");
		return entryList;
	}
	
	protected ArrayList<String> unpack(String idesPkgFile, PrivateKey privateKey, boolean isApprover) throws Exception {
		logger.debug("--> unpack(). idesPkg=" + idesPkgFile + ", isApprover=" + isApprover);
		boolean isRenameZip = false;
		ArrayList<String> entryList = unencryptZipPkg(idesPkgFile, privateKey, isApprover, isRenameZip);
		File file;
		String filename;
		ArrayList<String> tmpEntryList, outEntryList = null;
		for (int i = 0; i < entryList.size(); i++) {
			filename = entryList.get(i);
			if (filename.endsWith("zip")) {
				tmpEntryList = unzipFile(filename);
				file = new File(filename);
				if (file.exists()&&!file.delete())file.deleteOnExit();
				for (int j = 0; j < tmpEntryList.size(); j++) {
					if (outEntryList == null)
						outEntryList = new ArrayList<String>();
					outEntryList.add(tmpEntryList.get(j));
				}
			} else {
				if (outEntryList == null)
					outEntryList = new ArrayList<String>();
				outEntryList.add(filename);
			}
		}
		logger.debug("<-- unpack()");
		return outEntryList;
	}
	
	//this method creates IDES pkg for approver - model1 option2 
	public String createPkgWithApprover(String signedXmlFile, String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, 
			String approverGiin, X509Certificate approvercert, int taxyear, String fileFormat, 
			String binaryEncoding, String commType) throws Exception {
		logger.debug("--> createPkgWithApprover(). signedXmlFile= " + signedXmlFile + ", senderGiin=" + senderGiin + 
				", receiverGiin=" + receiverGiin + ", approverGiin=" + approverGiin + ", fileFormat=" + fileFormat + 
				", binaryEncoding=" + binaryEncoding + ", commType=" + commType);
		// if fileFormatCd=TXT|XML, binaryEncodingCd != BASE64. If fileFormatCd=PDF|JPG|RTF, binaryEncodingCd !=NONE
		if (fileFormat != null && binaryEncoding != null) {
			if (FileFormatCdType.TXT.value().equalsIgnoreCase(fileFormat) || FileFormatCdType.XML.value().equalsIgnoreCase(fileFormat)) {
				if (!BinaryEncodingSchemeCdType.NONE.value().equalsIgnoreCase(binaryEncoding))
					throw new Exception("incorrect combination. fileFormat=" + fileFormat + ", binaryEncoding=" + binaryEncoding);
			} else {
				if (!BinaryEncodingSchemeCdType.BASE_64.value().equalsIgnoreCase(binaryEncoding))
					throw new Exception("incorrect combination. fileFormat=" + fileFormat + ", binaryEncoding=" + binaryEncoding);
			}
		}
		String folder = new File(signedXmlFile).getAbsoluteFile().getParent();
		String xmlzipFilename = UtilShared.getTmpFileName(folder, senderGiin, "Payload.zip");
		createZipPkg(signedXmlFile, senderGiin, xmlzipFilename);
		String idesOutFile = encryptZipPkg(xmlzipFilename, senderGiin, receiverGiin, receiverPublicCert, 
				approverGiin, approvercert, taxyear, fileFormat, binaryEncoding, commType);
		File file = new File(xmlzipFilename);
		if (file.exists()&&!file.delete())file.deleteOnExit();
		logger.debug("<-- createPkgWithApprover()");
		return idesOutFile;
	}

	protected String signAndCreatePkgWithApprover(String unsignedXml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, String approverGiin, X509Certificate approverPublicCert, 
			int taxyear, String fileFormat, String binaryEncoding, String commType, boolean isStreaming) throws Exception {
		logger.debug("--> signAndCreatePkgWithApprover(). unsignedXml=" + unsignedXml + ", senderGiin=" + senderGiin + ", receiverGiin=" + 
			receiverGiin + ", approverGiin=" + approverGiin + ", taxyear=" + taxyear + ", fileFormat=" + fileFormat + 
			", binaryEncoding=" + binaryEncoding + ", commType=" + commType + ", isStreaming=" + isStreaming);
		String signedxml = UtilShared.getTmpFileName(unsignedXml, "signed.xml");
		boolean success = false;
		String ret = null;
		if (isStreaming)
			success = signer.signXmlFileStreaming(unsignedXml, signedxml, senderPrivateKey, senderPublicCert);
		else
			success = signer.signXmlFile(unsignedXml, signedxml, senderPrivateKey, senderPublicCert);
		if (success)
			ret = createPkgWithApprover(signedxml, senderGiin, receiverGiin, receiverPublicCert, approverGiin, approverPublicCert, taxyear, 
					fileFormat, binaryEncoding, commType);
		if (keepSignedXmlAfterSignAndCreatePkgFlag)
			UtilShared.renameToNextSequencedFile(signedxml, null, unsignedXml, ".signed.xml");
		else {
			File f = new File(signedxml);
			if (f.exists() && !f.delete()) f.deleteOnExit();
		}
		logger.debug("<-- signAndCreatePkgWithApprover()");
		return ret;
	}
	
	//this method wraps base64 binary in xml, signs and creates IDES pkg 
	protected String signBinaryFileAndCreatePkgWithApprover(String unsignedBinaryDoc, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, String approverGiin, X509Certificate approverPublicCert, 
			int taxyear, String fileFormat, String binaryEncoding, String commType, boolean isStreaming) throws Exception {
		logger.debug("--> signBinaryFileAndCreatePkgWithApprover(). unsignedXml=" + unsignedBinaryDoc + ", senderGiin=" + senderGiin + ", receiverGiin=" + 
			receiverGiin + ", taxyear=" + taxyear + ", fileFormat=" + fileFormat + ", binaryEncoding=" + binaryEncoding + 
			", commType=" + commType + ", isStreaming=" + isStreaming);
		String signedxml = UtilShared.getTmpFileName(unsignedBinaryDoc, "signed.xml");
		String ret = null;
		boolean success = false;
		if (isStreaming)
			success = signer.wrapBinaryFileInXmlAndSignStreaming(unsignedBinaryDoc, signedxml, senderPrivateKey, senderPublicCert);
		else
			success = signer.wrapBinaryFileInXmlAndSign(unsignedBinaryDoc, signedxml, senderPrivateKey, senderPublicCert);
		if (success)
			ret = createPkgWithApprover(signedxml, senderGiin, receiverGiin, receiverPublicCert, approverGiin, approverPublicCert, taxyear, 
					fileFormat, binaryEncoding, commType);
		File f = new File(signedxml);
		if (f.exists() && !f.delete()) f.deleteOnExit();
		logger.debug("<-- signBinaryFileAndCreatePkgWithApprover()");
		return ret;
	}
	
	//this method wraps text in xml, signs and creates IDES pkg 
	protected String signTextFileAndCreatePkgWithApprover(String unsignedText, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, String approverGiin, X509Certificate approverPublicCert, int taxyear, 
			String fileFormat, String binaryEncoding, String commType, boolean isStreaming) throws Exception {
		logger.debug("--> signTextFileAndCreatePkg(). unsignedXml=" + unsignedText + ", senderGiin=" + senderGiin + ", receiverGiin=" + 
			receiverGiin + ", taxyear=" + taxyear + ", fileFormat=" + fileFormat + ", binaryEncoding=" + binaryEncoding + 
			", isStreaming=" + isStreaming + ", commType=" + commType);
		String signedxml = UtilShared.getTmpFileName(unsignedText, "signed.xml");
		String ret = null;
		boolean success = false;
		if (isStreaming)
			success = signer.wrapTextFileInXmlAndSignStreaming(unsignedText, signedxml, senderPrivateKey, senderPublicCert);
		else
			success = signer.wrapTextFileInXmlAndSign(unsignedText, signedxml, senderPrivateKey, senderPublicCert);
		if (success)
			ret = createPkgWithApprover(signedxml, senderGiin, receiverGiin, receiverPublicCert, approverGiin, approverPublicCert, taxyear, 
					fileFormat, binaryEncoding, commType);
		File f = new File(signedxml);
		if (f.exists() && !f.delete()) f.deleteOnExit();
		logger.debug("<-- signTextFileAndCreatePkg()");
		return ret;
	}

	//this method takes zipped signed xml payload and creates IDES pkg 
	public String encryptZipPkg(String xmlzipFilename, String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, 
			String approverGiin, X509Certificate approverPublicCert, int taxyear, String fileFormat, String binaryEncoding, 
			String commType) throws Exception {
		logger.debug("--> encryptZipPkg(). xmlzipFilename= " + xmlzipFilename + ", senderGiin=" + senderGiin + 
				", receiverGiin=" + receiverGiin + ", approverGiin=" + approverGiin + ", taxyear=" + taxyear + 
				", fileFormat=" + fileFormat + ", binaryEncoding=" + binaryEncoding + ", commType=" + commType);
		boolean success = false;
		String folder = new File(xmlzipFilename).getAbsoluteFile().getParent();
		Date date = new Date();
		String idesOutFile = getPkgFileName(folder, senderGiin);
		File file = new File(idesOutFile);
		String senderFileId = file.getName();
		String metadatafile = null;
		metadatafile = metadata.createMetadata(folder, senderGiin, receiverGiin, commType, senderFileId, fileFormat, binaryEncoding, date, taxyear);
		Certificate[] certs = null;
		String[] encryptedAESKeyOutFiles = null;
		if (approverPublicCert != null && approverGiin != null) {
			certs = new X509Certificate[] {receiverPublicCert, approverPublicCert};
			encryptedAESKeyOutFiles = new String[]{UtilShared.getTmpFileName(folder, receiverGiin, "Key"), 
					UtilShared.getTmpFileName(folder, approverGiin, "Key")};
		} else if (receiverPublicCert != null){
			certs = new X509Certificate[] {receiverPublicCert};
			encryptedAESKeyOutFiles = new String[]{UtilShared.getTmpFileName(folder, receiverGiin, "Key")};
		} else
			throw new Exception ("both approvingEntityCert and receivingEntityCert is null");
		String xmlZippedEncryptedFile = UtilShared.getTmpFileName(folder, senderGiin, "Payload");
		success = encrypt(xmlzipFilename, xmlZippedEncryptedFile, certs, encryptedAESKeyOutFiles);
		if (! success)
			throw new Exception("encryption failed. xmlzipFilename=" + xmlzipFilename);
		int count = 0;
		String[] infiles = new String[encryptedAESKeyOutFiles.length + 2];
		for (count = 0; count < encryptedAESKeyOutFiles.length; count++)
			infiles[count] = encryptedAESKeyOutFiles[count];
		infiles[count++] =  xmlZippedEncryptedFile;
		infiles[count] = metadatafile;
		success = createZipFile(infiles, idesOutFile);
		if (success) {
			if (encryptedAESKeyOutFiles.length == 2)
				success = renameZipEntries(idesOutFile, new String[]{getFileName(xmlZippedEncryptedFile), getFileName(metadatafile), 
						getFileName(encryptedAESKeyOutFiles[0]), getFileName(encryptedAESKeyOutFiles[1])},
						new String[]{senderGiin + "_Payload", senderGiin + "_Metadata.xml", 
						receiverGiin + "_Key", approverGiin + "_Key"});
			else
				success = renameZipEntries(idesOutFile, new String[]{getFileName(xmlZippedEncryptedFile), getFileName(metadatafile), 
					getFileName(encryptedAESKeyOutFiles[0])},
					new String[]{senderGiin + "_Payload", senderGiin + "_Metadata.xml", 
					receiverGiin + "_Key"});
		}
		if (!success)
			throw new Exception("unable to create zip file " + idesOutFile);
		for (int i = 0; i < infiles.length; i++) {
			file = new File(infiles[i]);
			if (file.exists()&&!file.delete()) file.deleteOnExit();
		}
		logger.debug("<-- encryptZipPkg()");
		return idesOutFile;
	}
	
	//IFATCAPackagerExtended interface implementation
	//this method signs an XML using streaming api (to calculate signature digest) and creates IDES pkg
	public String signAndCreatePkgStreaming(String unsignedXml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, int taxyear, String commType) throws Exception {
		boolean isStreaming = true;
		String fileFormat = FileFormatCdType.XML.value();
		String binaryEncoding = BinaryEncodingSchemeCdType.NONE.value();
		String approverGiin = null; X509Certificate approverPublicCert = null;
		return signAndCreatePkgWithApprover(unsignedXml, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
				receiverPublicCert, approverGiin, approverPublicCert, taxyear, fileFormat, binaryEncoding, commType, isStreaming);
	}
	
	//this method signs an XML using streaming api (to calculate signature digest) and creates IDES pkg for approver - model1 option2 
	public String signAndCreatePkgWithApproverStreaming(String unsignedXml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, String approverGiin, X509Certificate approverPublicCert, 
			int taxyear, String commType) throws Exception {
		boolean isStreaming = true;
		String fileFormat = FileFormatCdType.XML.value();
		String binaryEncoding = BinaryEncodingSchemeCdType.NONE.value();
		return signAndCreatePkgWithApprover(unsignedXml, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
				receiverPublicCert, approverGiin, approverPublicCert, taxyear, fileFormat, binaryEncoding, commType, isStreaming);
	}
	
	//this method signs an XML using signature DOM api and creates IDES pkg - as DOM reads entire XML in memory, XML file size is restricted by heap 
	public String signAndCreatePkg(String unsignedXml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, int taxyear, String commType) throws Exception {
		boolean isStreaming = false;
		String fileFormat = FileFormatCdType.XML.value();
		String binaryEncoding = BinaryEncodingSchemeCdType.NONE.value();
		String approverGiin = null; X509Certificate approverPublicCert = null;
		return signAndCreatePkgWithApprover(unsignedXml, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
				receiverPublicCert, approverGiin, approverPublicCert, taxyear, fileFormat, binaryEncoding, commType, isStreaming);
	}
	
	//this method signs an XML using signature DOM api and creates IDES pkg for approver - model1 option2 - as DOM reads entire XML in memory, XML file size is restricted by heap 
	public String signAndCreatePkgWithApprover(String unsignedXml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, String approverGiin, X509Certificate approverPublicCert, 
			int taxyear, String commType) throws Exception {
		boolean isStreaming = false;
		String fileFormat = FileFormatCdType.XML.value();
		String binaryEncoding = BinaryEncodingSchemeCdType.NONE.value();
		return signAndCreatePkgWithApprover(unsignedXml, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
				receiverPublicCert, approverGiin, approverPublicCert, taxyear, fileFormat, binaryEncoding, commType, isStreaming);
	}
	
	//this method creates IDES pkg 
	public String createPkg(String signedXmlFile, String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, int taxyear,
			String fileFormat, String binaryEncoding, String commType) throws Exception {
		String approverGiin = null; X509Certificate approverPublicCert = null;
		return createPkgWithApprover(signedXmlFile, senderGiin, receiverGiin, receiverPublicCert, approverGiin, approverPublicCert, 
				taxyear, fileFormat, binaryEncoding, commType);
	}
	
	//this method unpack an IDES pkg 
	public ArrayList<String> unpack(String idesPkgFile, String keystoreType, String keystoreFile, String keystorePwd, String keyPwd, String keyAlias) throws Exception {
		logger.debug("--> unpack(). idesPkgFile=" + idesPkgFile + ", keystoreType=" + keystoreType + ", keystoreFile=" + keystoreFile + ", keyAlias=" + keyAlias);
		PrivateKey privateKey = UtilShared.getPrivateKey(keystoreType, keystoreFile, keystorePwd, keyPwd, keyAlias);
		ArrayList<String> ret = unpack(idesPkgFile, privateKey);
		logger.debug("<-- unpack()");
		return ret;
	}
	
	//this method unpack an IDES pkg 
	public ArrayList<String> unpack(String idesPkgFile, PrivateKey receiverPrivateKey) throws Exception {
		logger.debug("--> unpack(). idesPkgFile=" + idesPkgFile);
		boolean isApprover = false;
		ArrayList<String> ret = unpack(idesPkgFile, receiverPrivateKey, isApprover);
		logger.debug("<-- unpack()");
		return ret;
	}
	
	//this method unpack an IDES pkg for approver - model1 option2 
	public ArrayList<String> unpackForApprover(String idesPkgFile, String approverKeystoreType, String approverKeystoreFile, 
			String approverKeystorePwd, String approverKeyPwd, String approverKeyAlias) throws Exception {
		logger.debug("--> unpackForApprover(). idesPkgFile=" + idesPkgFile + ", approverKeystoreType=" + approverKeystoreType + ", approverKeystoreFile=" + approverKeystoreFile + ", approverKeyAlias=" + approverKeyAlias);
		PrivateKey approverPrivateKey = UtilShared.getPrivateKey(approverKeystoreType, approverKeystoreFile, approverKeystorePwd, approverKeyPwd, approverKeyAlias);
		ArrayList<String> ret = unpackForApprover(idesPkgFile, approverPrivateKey);
		logger.debug("<-- unpackForApprover()");
		return ret;
	}
	
	//this method unpack an IDES pkg for approver - model1 option2 
	public ArrayList<String> unpackForApprover(String idesPkgFile, PrivateKey approverPrivateKey) throws Exception {
		logger.debug("--> unpackForApprover(). idesPkgFile=" + idesPkgFile);
		ArrayList<String> ret = unpack(idesPkgFile, approverPrivateKey, true);
		logger.debug("<-- unpackForApprover()");
		return ret;
	}

	//this method wraps base64 binary in xml, signs and creates IDES pkg 
	public String signBinaryFileAndCreatePkg(String unsignedBinaryDoc, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, int taxyear, String fileFormat, 
			String commType) throws Exception {
		if (FileFormatCdType.XML.value().equalsIgnoreCase(fileFormat) || FileFormatCdType.TXT.value().equalsIgnoreCase(fileFormat) || fileFormat == null)
			throw new Exception("signBinaryFileAndCreatePkg()...invalid fileFormat=" + fileFormat);
		boolean isStreaming = false;
		String binaryEncoding = BinaryEncodingSchemeCdType.BASE_64.value();
		String approverGiin = null; X509Certificate approverPublicCert = null;
		return signBinaryFileAndCreatePkgWithApprover(unsignedBinaryDoc, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
				receiverPublicCert, approverGiin, approverPublicCert, taxyear, fileFormat, binaryEncoding, commType, isStreaming);
	}
	
	//this method wraps base64 binary in xml, signs and creates IDES pkg 
	public String signBinaryFileAndCreatePkgWithApprover(String unsignedBinaryDoc, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, String approverGiin, X509Certificate approverPublicCert, 
			int taxyear, String fileFormat, String commType) throws Exception {
		if (FileFormatCdType.XML.value().equalsIgnoreCase(fileFormat) || FileFormatCdType.TXT.value().equalsIgnoreCase(fileFormat) || fileFormat == null)
			throw new Exception("signBinaryFileAndCreatePkgWithApprover()...invalid fileFormat=" + fileFormat);
		boolean isStreaming = false;
		String binaryEncoding = BinaryEncodingSchemeCdType.BASE_64.value();
		return signBinaryFileAndCreatePkgWithApprover(unsignedBinaryDoc, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
				receiverPublicCert,	approverGiin, approverPublicCert, taxyear, fileFormat, binaryEncoding, commType, isStreaming);
	}
	
	public String signBinaryFileAndCreatePkgStreaming(String unsignedBinaryDoc, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, int taxyear, String fileFormat, 
			String commType) throws Exception {
		if (FileFormatCdType.XML.value().equalsIgnoreCase(fileFormat) || FileFormatCdType.TXT.value().equalsIgnoreCase(fileFormat) || fileFormat == null)
			throw new Exception("signBinaryFileAndCreatePkgStreaming()...invalid fileFormat=" + fileFormat);
		boolean isStreaming = true;
		String binaryEncoding = BinaryEncodingSchemeCdType.BASE_64.value();
		String approverGiin = null; X509Certificate approverPublicCert = null;
		return signBinaryFileAndCreatePkgWithApprover(unsignedBinaryDoc, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
				receiverPublicCert,	approverGiin, approverPublicCert, taxyear, fileFormat, binaryEncoding, commType, isStreaming);
	}
	
	public String signBinaryFileAndCreatePkgWithApproverStreaming(String unsignedBinaryDoc, PrivateKey senderPrivateKey, 
			X509Certificate senderPublicCert, String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, 
			String approverGiin, X509Certificate approverPublicCert, int taxyear, String fileFormat, String commType) throws Exception {
		if ("XML".equalsIgnoreCase(fileFormat) || "TXT".equalsIgnoreCase(fileFormat) || fileFormat == null)
			throw new Exception("signBinaryFileAndCreatePkgWithApproverStreaming()...invalid fileFormat=" + fileFormat);
		boolean isStreaming = true;
		String binaryEncoding = BinaryEncodingSchemeCdType.BASE_64.value();
		return signBinaryFileAndCreatePkgWithApprover(unsignedBinaryDoc, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
				receiverPublicCert,	approverGiin, approverPublicCert, taxyear, fileFormat, binaryEncoding, commType, isStreaming);
	}
	
	//this method wraps text in xml, signs and creates IDES pkg 
	public String signTextFileAndCreatePkg(String unsignedText, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, int taxyear, String commType) throws Exception {
		boolean isStreaming = false;
		String binaryEncoding = BinaryEncodingSchemeCdType.NONE.value();
		String fileFormat = FileFormatCdType.TXT.value();
		String approverGiin = null; X509Certificate approverPublicCert = null;
		return signTextFileAndCreatePkgWithApprover(unsignedText, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
				receiverPublicCert,	approverGiin, approverPublicCert, taxyear, fileFormat, binaryEncoding, commType, isStreaming);
	}
	
	//this method wraps text in xml, signs and creates IDES pkg 
	public String signTextFileAndCreatePkgWithApprover(String unsignedText, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, String approverGiin, X509Certificate approverPublicCert,
			int taxyear, String commType) throws Exception {
		boolean isStreaming = false;
		String binaryEncoding = BinaryEncodingSchemeCdType.NONE.value();
		String fileFormat = FileFormatCdType.TXT.value();
		return signTextFileAndCreatePkgWithApprover(unsignedText, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
				receiverPublicCert,	approverGiin, approverPublicCert, taxyear, fileFormat, binaryEncoding, commType, isStreaming);
	}
	
	public String signTextFileAndCreatePkgStreaming(String unsignedText, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, int taxyear, String commType) throws Exception {
		boolean isStreaming = true;
		String binaryEncoding = BinaryEncodingSchemeCdType.NONE.value();
		String fileFormat = FileFormatCdType.TXT.value();
		String approverGiin = null; X509Certificate approverPublicCert = null;
		return signTextFileAndCreatePkgWithApprover(unsignedText, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
				receiverPublicCert,	approverGiin, approverPublicCert, taxyear, fileFormat, binaryEncoding, commType, isStreaming);
	}
	
	public String signTextFileAndCreatePkgWithApproverStreaming(String unsignedText, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, String approverGiin, X509Certificate approverPublicCert, 
			int taxyear, String commType) throws Exception {
		boolean isStreaming = true;
		String binaryEncoding = BinaryEncodingSchemeCdType.NONE.value();
		String fileFormat = FileFormatCdType.TXT.value();
		return signTextFileAndCreatePkgWithApprover(unsignedText, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
				receiverPublicCert,	approverGiin, approverPublicCert, taxyear, fileFormat, binaryEncoding, commType, isStreaming);
	}

	public void setMetadataInfo(String emailAddress, String fileRevisionId, String origTranId) {
		metadata.setMetadataInfo(emailAddress, fileRevisionId, origTranId);
	}
	
	public IMetadata getMetadata() {
		return metadata;
	}

	public void setMetadata(IMetadata metadata) {
		this.metadata = metadata;
	}
}
