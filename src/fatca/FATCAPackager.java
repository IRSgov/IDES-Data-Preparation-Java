package fatca;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.log4j.Logger;

import com.sun.org.apache.xerces.internal.jaxp.datatype.XMLGregorianCalendarImpl;

import fatca.idessenderfilemetadata.FATCAEntCommunicationTypeCdType;
import fatca.idessenderfilemetadata.FATCAIDESSenderFileMetadataType;

public class FATCAPackager {
	public static String AES_TRANSFORMATION = "AES/ECB/PKCS5Padding";
	public static String RSA_TRANSFORMATION = "RSA";
	public static String SECRET_KEY_ALGO = "AES";
	public static int SECRET_KEY_SIZE = 256;

	public static String metadataEmailAddress="none@email.com";
	public static int bufSize = 64 * 1024;

	public static boolean isCanonicalization = true;
	
	protected static Logger logger = Logger.getLogger(new Object(){}.getClass().getEnclosingClass().getName());

	protected FATCAXmlSigner signer = new FATCAXmlSigner();
	protected Long fileId = 0L;
	protected fatca.idessenderfilemetadata.ObjectFactory objFMetadata = new fatca.idessenderfilemetadata.ObjectFactory();
	protected SimpleDateFormat sdfFileName = new SimpleDateFormat("yyyyMMdd'T'HHmmssSSS'Z'");
	protected SimpleDateFormat sdfFileCreateTs = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
	
	protected int maxAttempts = 5;
	
	protected boolean aes(int opmode, String inputFile, String outputFile, SecretKey secretKey) throws Exception {
		logger.debug("--> aes(). opmode=" + (opmode==Cipher.ENCRYPT_MODE?"ENCRYPT":"DECRYPT") + 
			", inputFile=" + inputFile + ", outputFile=" + outputFile);
		if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE)
			throw new Exception("Invalid opmode " + opmode + ". Allowed opmodes are Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE");
		boolean ret = false;
		BufferedInputStream bis = null;
		BufferedOutputStream bos = null;
		int len;
		byte[] output = null;
		byte[] buf = new byte[bufSize];
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(AES_TRANSFORMATION);
			cipher.init(opmode, secretKey);
			bis = new BufferedInputStream(new FileInputStream(inputFile));
			bos = new BufferedOutputStream(new FileOutputStream(outputFile));
			while((len = bis.read(buf)) != -1) {
				//output = cipher.update(Arrays.copyOf(buf, len));
				output = cipher.update(buf, 0, len);
				if (output.length > 0)
					bos.write(output);
			}
			output = cipher.doFinal();
			if (output.length > 0)
				bos.write(output);
			bos.close(); bos = null;
			bis.close(); bis = null; 
			ret = true;
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			throw e;
		} finally {
			if (bis != null) try{bis.close();}catch(Exception e) {}
			if (bos != null) try{bos.close();}catch(Exception e) {}
		}
		logger.debug("<-- aes()");
		return ret;
	}
	
	protected boolean encrypt(String zippedSignedPlainTextFile, String cipherTextOutFile, Certificate[] receiversPublicCert,
			String[] encryptedAESKeyOutFiles) throws Exception {
		logger.debug("--> encrypt(). zippedSignedPlainTextFile=" + zippedSignedPlainTextFile + ", cipherTextOutFile=" + cipherTextOutFile);
		PublicKey[] pubkeys = new PublicKey[receiversPublicCert.length];
		for (int i = 0; i < receiversPublicCert.length; i++)
			pubkeys[i] = receiversPublicCert[i].getPublicKey();
		boolean flag = encrypt(zippedSignedPlainTextFile, cipherTextOutFile, pubkeys, encryptedAESKeyOutFiles);
		logger.debug("<-- encrypt()");
		return flag;
	}
	
	protected boolean encrypt(String zippedSignedPlainTextFile, String cipherTextOutFile, PublicKey[] receiversPublicKey,
			String[] encryptedAESKeyOutFiles) throws Exception {
		logger.debug("--> encrypt(). zippedSignedPlainTextFile=" + zippedSignedPlainTextFile + ", cipherTextOutFile" + cipherTextOutFile);
		boolean ret = false;
		SecretKey skey = null;
		KeyGenerator generator;
		byte[] encryptedAESKeyBuf;
		BufferedOutputStream bos = null;
		Cipher cipher = null;
		try {
			generator = KeyGenerator.getInstance(SECRET_KEY_ALGO);
			generator.init(SECRET_KEY_SIZE);
			skey = generator.generateKey();
			ret = aes(Cipher.ENCRYPT_MODE, zippedSignedPlainTextFile, cipherTextOutFile, skey);
			if (ret) {
				for (int i = 0; i < receiversPublicKey.length && i < encryptedAESKeyOutFiles.length; i++) {
					if (cipher == null)
						cipher = Cipher.getInstance(RSA_TRANSFORMATION);
					cipher.init(Cipher.WRAP_MODE, receiversPublicKey[i]);
					encryptedAESKeyBuf = cipher.wrap(skey);
					bos = new BufferedOutputStream(new FileOutputStream(encryptedAESKeyOutFiles[i]));
					bos.write(encryptedAESKeyBuf);
					bos.close(); bos = null;
				}
				ret = true;
			}
		} catch(Exception e) {
			logger.error(e.getMessage(), e);
			throw e;
		} finally {
			if (bos != null) try{bos.close();}catch(Exception e) {}
		}
		logger.debug("<-- encrypt)");
		return ret;
	}
	
	protected boolean renameZipEntry(String zipFile, String entryName, String newEntryName) throws Exception {
		logger.debug("--> renameZipEntry(). zipFile=" + zipFile + ", entryName=" + entryName + ", newEntryName=" + newEntryName);
		boolean ret = false;
        Map<String, String> props = new HashMap<String, String>(); 
        props.put("create", "false"); 
        try {
            URI zipDisk = URI.create("jar:" + new File(zipFile).toURI());
            FileSystem zipfs = FileSystems.newFileSystem(zipDisk, props);
            Path pathInZipfile = zipfs.getPath(entryName);
            Path renamedZipEntry = zipfs.getPath(newEntryName);
            Files.move(pathInZipfile,renamedZipEntry, StandardCopyOption.ATOMIC_MOVE);
            zipfs.close();
            ret = true;
        } catch(Exception e) {
			logger.error(e.getMessage(), e);
			throw e;
        }
		logger.debug("<-- renameZipEntry()");
		return ret;
	}
	
	protected boolean renameZipEntries(String zipFile, String[] entryNames, String[] newEntryNames) throws Exception {
		if (logger.isDebugEnabled()) {
			StringBuilder sb = new StringBuilder("--> renameZipEntries()");
			sb.append(", zipFile=");
			sb.append(zipFile);
			sb.append(", entryNames=[");
			for (int i = 0; i < entryNames.length; i++) {
				if (i > 0) sb.append(",");
				sb.append(entryNames[i]);
			}
			sb.append("], newEntryNames=[");
			for (int i = 0; i < newEntryNames.length; i++) {
				if (i > 0) sb.append(",");
				sb.append(newEntryNames[i]);
			}
			sb.append("]");
			logger.debug(sb.toString());
		}
		boolean ret = false;
		if (entryNames.length != newEntryNames.length)
			throw new Exception("renameZipEntries entryNames and newEntryNames length should be same");
        Map<String, String> props = new HashMap<String, String>(); 
        props.put("create", "false"); 
        try {
            URI zipDisk = URI.create("jar:" + new File(zipFile).toURI());
        	FileSystem zipfs = FileSystems.newFileSystem(zipDisk, props);
        	Path pathInZipfile, renamedZipEntry;
        	for (int i = 0; i < entryNames.length; i++) {
                pathInZipfile = zipfs.getPath(entryNames[i]);
                renamedZipEntry = zipfs.getPath(newEntryNames[i]);
                Files.move(pathInZipfile,renamedZipEntry, StandardCopyOption.ATOMIC_MOVE);
        	}
            zipfs.close();
            ret = true;
        } catch(Exception e) {
			logger.error(e.getMessage(), e);
			throw e;
        }
		logger.debug("<-- renameZipEntries()");
		return ret;
	}
	
	protected boolean createZipFile(String[] inFiles, String outFile) throws Exception {
		if (logger.isDebugEnabled()) {
			StringBuilder sb = new StringBuilder("--> createZipFile()");
			sb.append(", inFiles=[");
			for (int i = 0; i < inFiles.length; i++) {
				if (i > 0) sb.append(",");
				sb.append(inFiles[i]);
			}
			sb.append("], outFile=");
			sb.append(outFile);
			logger.debug(sb.toString());
		}
		BufferedInputStream bis = null;
		ZipOutputStream zos = null;
		ZipEntry zipEntry;
		int len;
		boolean ret = false;
		String infile;
		byte[] buf = new byte[bufSize];
		try {
			zos = new ZipOutputStream(new FileOutputStream(outFile));
			zos.setLevel(Deflater.BEST_COMPRESSION);
			for (int i = 0; i < inFiles.length; i++) {
				// drop folder names
				infile = inFiles[i];
				len = infile.lastIndexOf("/");
				if (len == -1)
					len = infile.lastIndexOf("\\");
				if (len != -1)
					infile = infile.substring(len+1);
				zipEntry = new ZipEntry(infile);
				zos.putNextEntry(zipEntry);
				bis = new BufferedInputStream(new FileInputStream(inFiles[i]));
				while((len = bis.read(buf)) != -1)
					zos.write(buf, 0, len);
				bis.close(); bis = null;
				zos.closeEntry();
			}
			zos.close(); zos = null;
			ret = true;
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			throw e;
		} finally {
			if (bis != null) try{bis.close();}catch(Exception e) {}
			if (zos != null) try{zos.close();}catch(Exception e) {}
		}
		logger.debug("<-- createZipFile()");
    	return ret;
	}

	protected ArrayList<String> unzipFile(String inFile) throws Exception {
		return unzipFile(inFile, null);
	}
	
	protected ArrayList<String> unzipFile(String inFile, String extractFolder) throws Exception {
		logger.debug("--> unzipFile(). inFile=" + inFile + ", extractFolder=" + extractFolder);
    	BufferedInputStream bis = null;
    	BufferedOutputStream bos = null;
    	int len;
    	ZipFile zipFile = null;
    	Enumeration<? extends ZipEntry> entries;
    	ZipEntry entry;
    	ArrayList<String> entryList = null;
    	byte[] buf = new byte[bufSize];
    	String outFile;
		try {
			if (extractFolder == null)
				extractFolder = ".";
			if (!extractFolder.endsWith("/") && !extractFolder.endsWith("\\"))
				extractFolder += "/";
			zipFile = new ZipFile(inFile);
	    	entries = zipFile.entries();
	    	while (entries.hasMoreElements()) {
	    		if (entryList == null)
		    		entryList = new ArrayList<String>();
	    		entry = entries.nextElement();
	    		outFile = extractFolder + entry.getName();
	    		entryList.add(outFile);
	    		bis = new BufferedInputStream(zipFile.getInputStream(entry));
	    		bos = new BufferedOutputStream(new FileOutputStream(outFile));
	    		while((len = bis.read(buf)) != -1)
	    			bos.write(buf, 0, len);
	    		bos.close(); bos = null;
	    		bis.close(); bis = null;
	    	}
	    	zipFile.close(); zipFile = null;
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			throw e;
		} finally {
			if (bis != null) try{bis.close();}catch(Exception e) {}
			if (bos != null) try{bos.close();}catch(Exception e) {}
			if (zipFile != null) try{zipFile.close();}catch(Exception e) {}
		}
		logger.debug("<-- unzipFile()");
		return entryList;
	}

	//_Payload.xml,_Metadata.xml, _Payload.zip, _Key, _Payload
	protected String getFileName(String senderGiin, String filename) throws Exception {
		synchronized (fileId) {
			logger.debug("--> getFileName(). senderGiin=" + senderGiin + ", filename=" + filename);
			if (fileId == Long.MAX_VALUE) fileId = 0L;
			String xmlfilename = senderGiin + "_" + fileId++ + filename;
			File file = new File(xmlfilename);
			int attempts = maxAttempts;
			while(!file.createNewFile() && attempts-- > 0) {
				xmlfilename = senderGiin + "_" + fileId++ + filename;
				file = new File(xmlfilename);
			}
			if (attempts <= 0)
				throw new Exception ("Unable to getFileName() - file=" + file.getAbsolutePath());
			logger.debug("<-- getFileName()");
			return xmlfilename;
		}
	}
	
	protected String getIDESFileName(String senderGiin) throws Exception {
		synchronized (fileId) {
			logger.debug("--> getIDESFileName(). senderGiin=" + senderGiin);
			Date date = new Date();
			String outfile = sdfFileName.format(date) + "_" + senderGiin + ".zip";
			File file = new File(outfile);
			int attempts = maxAttempts;
			while (!file.createNewFile() && attempts-- > 0) {
				outfile = sdfFileName.format(new Date()) + "_" + senderGiin + ".zip";
				file = new File(outfile);
			}
			if (attempts <= 0)
				throw new Exception ("Unable to getFileName() - file=" + file.getAbsolutePath());
			logger.debug("<-- getIDESFileName()");
			return outfile;
		}
	}
	
	protected XMLGregorianCalendar genTaxYear(int year) {
		XMLGregorianCalendar taxyear = new XMLGregorianCalendarImpl(new GregorianCalendar());
		taxyear.setTimezone(DatatypeConstants.FIELD_UNDEFINED);
		taxyear.setTime(DatatypeConstants.FIELD_UNDEFINED, DatatypeConstants.FIELD_UNDEFINED, DatatypeConstants.FIELD_UNDEFINED);
		taxyear.setDay(DatatypeConstants.FIELD_UNDEFINED);
		taxyear.setMonth(DatatypeConstants.FIELD_UNDEFINED);
		taxyear.setYear(year);
		return taxyear;
	}
	
	protected String getFileName(String filename) {
		File f = new File(filename);
		return f.getName();
	}
	
	public String signAndCreatePkg(String unsignedXml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, int taxyear) throws Exception {
		logger.debug("--> signAndCreatePkg(). unsignedXml=" + unsignedXml + ", senderGiin=" + senderGiin +
				", receiverGiin=" + receiverGiin + ", taxyear=" + taxyear);
		String signedxml = unsignedXml + ".signed";
		boolean success = false;
		String ret = null;
		if (isCanonicalization)
			success = signer.signStreamingWithCanonicalization(unsignedXml, signedxml, senderPrivateKey, senderPublicCert);
		else
			success = signer.signStreaming(unsignedXml, signedxml, senderPrivateKey, senderPublicCert);
		if (success)
			ret = createPkgWithApprover(signedxml, senderGiin, receiverGiin, receiverPublicCert, null, null, taxyear);
		logger.debug("<-- signAndCreatePkg()");
		return ret;
	}
	
	public String signAndCreatePkgWithApprover(String unsignedxml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, String approverGiin, 
			X509Certificate approvercert, int taxyear) throws Exception {
		logger.debug("--> signAndCreatePkgWithApprover(). xmlfilename=" + unsignedxml + ", senderGiin=" + senderGiin +
				", receiverGiin=" + receiverGiin + ", approverGiin=" + approverGiin + ", taxyear=" + taxyear);
		String signedxml = unsignedxml + ".signed";
		boolean success = false;
		String ret = null;
		if (isCanonicalization)
			success = signer.signStreamingWithCanonicalization(unsignedxml, signedxml, senderPrivateKey, senderPublicCert);
		else
			success = signer.signStreaming(unsignedxml, signedxml, senderPrivateKey, senderPublicCert);
		if (success)
			ret = createPkgWithApprover(signedxml, senderGiin, receiverGiin, receiverPublicCert, approverGiin, approvercert, taxyear);
		logger.debug("<-- signAndCreatePkgWithApprover()");
		return ret;
	}
	
	public String createPkg(String signedXmlFile, String senderGiin, String receiverGiin,  
			X509Certificate receiverPublicCert, int taxyear) throws Exception {
		return createPkgWithApprover(signedXmlFile, senderGiin, receiverGiin, receiverPublicCert, null, null, taxyear);
	}
	
	public String createPkgWithApprover(String signedXmlFile, String senderGiin, String receiverGiin,  
			X509Certificate receiverPublicCert, String approverGiin, 
			X509Certificate approvercert, int taxyear) throws Exception {
		logger.debug("--> createPkgWithApprover(). signedXmlFile= " + signedXmlFile + ", senderGiin=" + senderGiin + 
				", receiverGiin=" + receiverGiin + ", approverGiin=" + approverGiin);
		String idesOutFile = null;
		try {
			Date date = new Date();
			String metadatafile = getFileName(senderGiin, "_Metadata.xml");
			JAXBContext jaxbCtxMetadata = JAXBContext.newInstance(FATCAIDESSenderFileMetadataType.class);            
			Marshaller mrshler = jaxbCtxMetadata.createMarshaller();
			mrshler.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
			
			FATCAIDESSenderFileMetadataType metadata = objFMetadata.createFATCAIDESSenderFileMetadataType();
			JAXBElement<FATCAIDESSenderFileMetadataType> jaxbElemMetadata = objFMetadata.createFATCAIDESSenderFileMetadata(metadata);
			
			metadata.setFATCAEntCommunicationTypeCd(FATCAEntCommunicationTypeCdType.RPT);
			metadata.setFATCAEntitySenderId(senderGiin);
			metadata.setFileRevisionInd(false);
			String senderFileId = getIDESFileName(senderGiin);
			File file = new File(senderFileId);
			metadata.setSenderFileId(file.getName());
			metadata.setTaxYear(genTaxYear(taxyear));
			metadata.setFATCAEntityReceiverId(receiverGiin);
			metadata.setFileCreateTs(sdfFileCreateTs.format(date));
			metadata.setSenderContactEmailAddressTxt(metadataEmailAddress);
			FileWriter fw = new FileWriter(metadatafile);
			mrshler.marshal(jaxbElemMetadata, fw);
			fw.close();
			String xmlzipFilename;
			boolean success = false;
			xmlzipFilename = getFileName(senderGiin, "_Payload.zip");
			success = createZipFile(new String[]{signedXmlFile}, xmlzipFilename);
			if (success)
				success = renameZipEntry(xmlzipFilename, getFileName(signedXmlFile), senderGiin + "_Payload.xml");
			if (!success)
				throw new Exception("uanble to create " + xmlzipFilename);
			idesOutFile = senderFileId;
			Certificate[] certs = null;
			String[] encryptedAESKeyOutFiles = null;
			if (approvercert != null && approverGiin != null) {
				certs = new X509Certificate[] {receiverPublicCert, approvercert};
				encryptedAESKeyOutFiles = new String[]{getFileName(receiverGiin, "_Key"), getFileName(approverGiin, "_Key")};
			} else if (receiverPublicCert != null){
				certs = new X509Certificate[] {receiverPublicCert};
				encryptedAESKeyOutFiles = new String[]{getFileName(receiverGiin, "_Key")};
			} else
				throw new Exception ("both approvingEntityCert and receivingEntityCert is null");
			String xmlZippedEncryptedFile = getFileName(senderGiin, "_Payload");
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
			for (int i = 0; i < infiles.length; i++)
				deleteFile(infiles[i]);
			deleteFile(xmlzipFilename);
			//deleteFile(signedXmlFile);
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
		logger.debug("<-- createPkgWithApprover()");
		return idesOutFile;
	}

	protected boolean decrypt(String cipherTextFile, String encryptedAESKeyFile, String zippedSignedPlainTextFile, PrivateKey privkey) throws Exception {
		logger.debug("--> decrypt(). cipherTextFile= " + cipherTextFile + ", encryptedAESKeyFile=" + encryptedAESKeyFile + 
				", zippedSignedPlainTextFile=" + zippedSignedPlainTextFile);
		SecretKey skey;
		boolean ret = false;
		BufferedInputStream bis = null;
		byte[] buf, skeyBuf = null;
		int len, count;
		try {
			buf = new byte[bufSize];
			bis = new BufferedInputStream(new FileInputStream(encryptedAESKeyFile));
			while((len = bis.read(buf)) != -1) {
				if (skeyBuf == null) {
					skeyBuf = new byte[len];
					System.arraycopy(buf, 0, skeyBuf, 0, len);
				} else {
					count = skeyBuf.length;
					skeyBuf = Arrays.copyOf(skeyBuf, skeyBuf.length + len);
					System.arraycopy(buf, 0, skeyBuf, count, len);
				}
			}
			bis.close(); bis = null;
			Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
			cipher.init(Cipher.UNWRAP_MODE, privkey);
			skey = (SecretKey)cipher.unwrap(skeyBuf, SECRET_KEY_ALGO, Cipher.SECRET_KEY);
			ret = aes(Cipher.DECRYPT_MODE, cipherTextFile, zippedSignedPlainTextFile, skey);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			throw e;
		} finally {
			if (bis != null) try{bis.close();}catch(Exception e) {}
		}
		logger.debug("<-- createPkgWithApprover()");
		return ret;
	}
	
	protected void deleteFile(String filename) {
		File file = new File(filename);
		int attempts = maxAttempts;
		while (file.exists() && !file.delete() && attempts-->0)
			Thread.yield();
	}

	public boolean unpack(String idesPkgFile, String keystoreType, String keystoreFile, String keystorePwd, String keyPwd, String keyAlias) throws Exception {
		logger.debug("--> unpack(). idesPkgFile=" + idesPkgFile + ", keystoreType=" + keystoreType + 
				", keystoreFile=" + keystoreFile + ", keyAlias=" + keyAlias);
		PrivateKey privateKey = UtilShared.getPrivateKey(keystoreType, keystoreFile, keystorePwd, keyPwd, keyAlias);
		boolean flag = unpack (idesPkgFile, privateKey);
		logger.debug("<-- unpack()");
		return flag;
	}
	
	public boolean unpack(String idesPkgFile, PrivateKey receiverPrivateKey) throws Exception {
		logger.debug("--> unpack(). idesPkgFile=" + idesPkgFile);
		boolean flag = unpack(idesPkgFile, receiverPrivateKey, false);
		logger.debug("<-- unpack()");
		return flag;
	}
	
	public boolean unpackForApprover(String idesPkgFile, String approverKeystoreType, String approverKeystoreFile, 
			String approverKeystorePwd, String approverKeyPwd, String approverKeyAlias) throws Exception {
		logger.debug("--> unpackForApprover(). idesPkgFile=" + idesPkgFile + ", approverKeystoreType=" + approverKeystoreType + 
				", approverKeystoreFile=" + approverKeystoreFile + ", approverKeyAlias=" + approverKeyAlias);
		PrivateKey approverPrivateKey = UtilShared.getPrivateKey(approverKeystoreType, approverKeystoreFile, approverKeystorePwd, approverKeyPwd, approverKeyAlias);
		boolean flag = unpackForApprover(idesPkgFile, approverPrivateKey);
		logger.debug("<-- unpackForApprover()");
		return flag;
	}
	
	public boolean unpackForApprover(String idesPkgFile, PrivateKey approverPrivateKey) throws Exception {
		logger.debug("--> unpackForApprover(). idesPkgFile=" + idesPkgFile);
		boolean flag = unpack(idesPkgFile, approverPrivateKey, true);
		logger.debug("<-- unpackForApprover()");
		return flag;
	}
	
	protected boolean unpack(String idesPkgFile, PrivateKey privateKey, boolean isApprover) throws Exception {
		logger.debug("--> unpack(). idesPkg=" + idesPkgFile + ", isApprover=" + isApprover);
		boolean ret = false;
		try {
			ArrayList<String> entryList = unzipFile(idesPkgFile);
			String approverKeyFile = null, receiverKeyFile = null, payloadFile = null, metadataFile = null,  receiverGiin = null, filename;
			// get metadata file
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

			if (approverKeyFile != null) {
				JAXBContext jaxbCtxMetadata = JAXBContext.newInstance("fatca.idessenderfilemetadata");
				Unmarshaller unmrshlr = jaxbCtxMetadata.createUnmarshaller();
				Object obj = unmrshlr.unmarshal(new File(metadataFile));;
				if (obj instanceof JAXBElement<?>) {
					@SuppressWarnings("unchecked")
					JAXBElement<FATCAIDESSenderFileMetadataType> jaxbElem = 
						(JAXBElement<FATCAIDESSenderFileMetadataType>)obj;
					FATCAIDESSenderFileMetadataType metadataObj = jaxbElem.getValue();
					receiverGiin = metadataObj.getFATCAEntityReceiverId();
					if (!receiverKeyFile.contains(receiverGiin)) {
						filename = approverKeyFile;
						approverKeyFile = receiverKeyFile;
						receiverKeyFile = filename;
					}
				}
			} else if (receiverKeyFile != null)
				receiverGiin = receiverKeyFile.substring(0, receiverKeyFile.length() - "_Key".length());
			if (receiverGiin == null)
				throw new Exception("Invalid metadata file - missing receiver giin or corrupt zip file - no reveiverKeyFile");
			if (isApprover && approverKeyFile == null)
				throw new Exception("Invalid package - no approverKeyFile");
			String zippedSignedPlainTextFile = getFileName(receiverGiin, "_Payload.zip");
			if (approverKeyFile != null && isApprover)
				ret = decrypt(payloadFile, approverKeyFile, zippedSignedPlainTextFile, privateKey);
			else
				ret = decrypt(payloadFile, receiverKeyFile, zippedSignedPlainTextFile, privateKey);

			if (ret) {
				if (unzipFile(zippedSignedPlainTextFile) == null)
					ret = false;
				else
					deleteFile(zippedSignedPlainTextFile);
			}
			deleteFile(payloadFile);
			//deleteFile(metadataFile);
			deleteFile(receiverKeyFile);
			if (approverKeyFile != null)
				deleteFile(approverKeyFile);
		} catch(Exception e) {
			logger.error(e.getMessage());
			throw e;
		}
		logger.debug("<-- unpack()");
		return ret;
	}
}
