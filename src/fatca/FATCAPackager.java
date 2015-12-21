package fatca;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
//import java.nio.file.FileSystem;
//import java.nio.file.FileSystems;
//import java.nio.file.Files;
//import java.nio.file.Path;
//import java.nio.file.StandardCopyOption;
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

import fatca.FATCAXmlSigner.SigRefIdPos;
import fatca.FATCAXmlSigner.SigXmlTransform;

/*
 * @author	Subir Paul (IT:ES:SE:PE)
 * 
 */
public class FATCAPackager {
	// NOTE: all public methods and vars are thread unsafe
	protected String AES_TRANSFORMATION = "AES/ECB/PKCS5Padding";
	protected String RSA_TRANSFORMATION = "RSA";
	protected String SECRET_KEY_ALGO = "AES";
	protected int SECRET_KEY_SIZE = 256;
	protected String metadataEmailAddress="none@email.com";
	protected Logger logger = Logger.getLogger(new Object(){}.getClass().getEnclosingClass().getName());

	protected fatca.idessenderfilemetadata.ObjectFactory objFMetadata1_0 = new fatca.idessenderfilemetadata.ObjectFactory();
	protected SimpleDateFormat sdfFileName = new SimpleDateFormat("yyyyMMdd'T'HHmmssSSS'Z'");
	protected SimpleDateFormat sdfFileCreateTs = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
	protected JAXBContext jaxbCtxMetadata1_0;
	
	protected int defaultBufSize = 8 * 1024;
	protected MyThreadSafeData myThreadSafeData = new MyThreadSafeData();

	private class MyThreadSafeData {
		private Integer bufSize = defaultBufSize;
		private FATCAXmlSigner signer = new FATCAXmlSigner();
	    public synchronized FATCAXmlSigner getSigner() {
			return signer;
		}

		public synchronized void setSigner(FATCAXmlSigner signer) {
			this.signer = signer;
		}

		public void setBufSize(int val) {
	    	synchronized (bufSize) {
				bufSize = val;
			}
		}

	    public int getBufSize() {
	    	synchronized (bufSize) {
				return bufSize;
			}
		}
	}
	
	public FATCAPackager() {
		try {
			jaxbCtxMetadata1_0 = JAXBContext.newInstance("fatca.idessenderfilemetadata");
		} catch(Throwable t) {
			t.printStackTrace();
			throw new RuntimeException(t);
		}
	}
	
	protected boolean aes(int opmode, String inputFile, String outputFile, SecretKey secretKey) throws Exception {
		logger.debug("--> aes(). opmode=" + (opmode==Cipher.ENCRYPT_MODE?"ENCRYPT":"DECRYPT") + ", inputFile=" + inputFile + ", outputFile=" + outputFile);
		if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE)
			throw new Exception("Invalid opmode " + opmode + ". Allowed opmodes are Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE");
		boolean ret = false;
		BufferedInputStream bis = null;
		BufferedOutputStream bos = null;
		int len;
		byte[] output = null;
		byte[] buf = new byte[getBufSize()];
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(AES_TRANSFORMATION);
			cipher.init(opmode, secretKey);
			bis = new BufferedInputStream(new FileInputStream(new File(inputFile)));
			bos = new BufferedOutputStream(new FileOutputStream(new File(outputFile)));
			while((len = bis.read(buf)) != -1) {
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
					bos = new BufferedOutputStream(new FileOutputStream(new File(encryptedAESKeyOutFiles[i])));
					bos.write(encryptedAESKeyBuf);
					bos.close(); bos = null;
				}
				ret = true;
			}
		} finally {
			if (bos != null) try{bos.close();}catch(Exception e) {}
		}
		logger.debug("<-- encrypt)");
		return ret;
	}

	/* JRE 7 or up
	protected boolean renameZipEntry(String zipFile, String entryName, String newEntryName) throws Exception {
		logger.debug("--> renameZipEntry(). zipFile=" + zipFile + ", entryName=" + entryName + ", newEntryName=" + newEntryName);
		boolean ret = false;
        Map<String, String> props = new HashMap<String, String>(); 
        props.put("create", "false"); 
        URI zipDisk = URI.create("jar:" + new File(zipFile).toURI());
        FileSystem zipfs = FileSystems.newFileSystem(zipDisk, props);
        Path pathInZipfile = zipfs.getPath(entryName);
        Path renamedZipEntry = zipfs.getPath(newEntryName);
        Files.move(pathInZipfile,renamedZipEntry, StandardCopyOption.ATOMIC_MOVE);
        zipfs.close();
        ret = true;
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
		logger.debug("<-- renameZipEntries()");
		return ret;
	}
	*/
	
	public boolean createZipFile(String[] inFiles, String outFile) throws Exception {
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
		byte[] buf = new byte[myThreadSafeData.getBufSize()];
		try {
			zos = new ZipOutputStream(new FileOutputStream(new File(outFile)));
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
				bis = new BufferedInputStream(new FileInputStream(new File(inFiles[i])));
				while((len = bis.read(buf)) != -1)
					zos.write(buf, 0, len);
				bis.close(); bis = null;
				zos.closeEntry();
			}
			zos.close(); zos = null;
			ret = true;
		} finally {
			if (bis != null) try{bis.close();}catch(Exception e) {}
			if (zos != null) try{zos.close();}catch(Exception e) {}
		}
		logger.debug("<-- createZipFile()");
    	return ret;
	}
	
	// for JRE 6. If you have JRE 7 use JRE 7 version
	protected boolean renameZipEntry(String zipFile, String entryName, String newEntryName) throws Exception {
		logger.debug("--> renameZipEntry(). zipFile=" + zipFile + ", entryName=" + entryName + ", newEntryName=" + newEntryName);
		boolean ret = false;
		ZipFile inzip = new ZipFile(zipFile);
		String tmpfile = UtilShared.getTmpFileName(zipFile, "tmp");
		ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(new File(tmpfile)));
		ZipEntry entry, newentry;
		InputStream is;
		Enumeration<? extends ZipEntry> e = inzip.entries();
		byte[] buf = new byte[8*1024];
		int len;
		while (e.hasMoreElements()) {
			entry = e.nextElement();
			is = inzip.getInputStream(entry);
			if (entryName.equalsIgnoreCase(entry.getName()))
				newentry = new ZipEntry(newEntryName);
			else
				newentry = new ZipEntry(entry.getName());
			zos.putNextEntry(newentry);
			while((len = is.read(buf)) != -1) {
				zos.write(buf, 0, len);
			}
			is.close();
			zos.closeEntry();
		}
		zos.close();
		inzip.close();
		File dest = new File(zipFile);
		File src = new File(tmpfile);
		UtilShared.deleteDestAndRenameFile(src, dest);
		ret = true;
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
		ZipFile inzip = new ZipFile(zipFile);
		String tmpfile = UtilShared.getTmpFileName(zipFile, "tmp");
		ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(new File(tmpfile)));
		ZipEntry entry, newentry;
		InputStream is;
		Enumeration<? extends ZipEntry> e = inzip.entries();
		byte[] buf = new byte[8*1024];
		int len;
		while (e.hasMoreElements()) {
			entry = e.nextElement();
			is = inzip.getInputStream(entry);
			newentry = null;
			for (int i = 0; i < entryNames.length; i++) {
				if (entryNames[i].equalsIgnoreCase(entry.getName())) {
					newentry = new ZipEntry(newEntryNames[i]);
					break;
				}
			}
			if (newentry == null)
				newentry = new ZipEntry(entry.getName());
			zos.putNextEntry(newentry);
			while((len = is.read(buf)) != -1) {
				zos.write(buf, 0, len);
			}
			is.close();
			zos.closeEntry();
		}
		zos.close();
		inzip.close();
		File dest = new File(zipFile);
		File src = new File(tmpfile);
		UtilShared.deleteDestAndRenameFile(src, dest);
		ret = true;
		logger.debug("<-- renameZipEntries()");
		return ret;
	}
	
	public ArrayList<String> unzipFile(String inFile) throws Exception {
		String workingDir = new File(inFile).getAbsoluteFile().getParent();
		if (!"".equals(workingDir) && !workingDir.endsWith("/") && !workingDir.endsWith("\\"))
			workingDir += File.separator;
		return unzipFile(inFile, workingDir);
	}
	
	public ArrayList<String> unzipFile(String inFile, String extractFolder) throws Exception {
		logger.debug("--> unzipFile(). inFile=" + inFile + ", extractFolder=" + extractFolder);
    	BufferedInputStream bis = null;
    	BufferedOutputStream bos = null;
    	int len;
    	ZipFile zipFile = null;
    	Enumeration<? extends ZipEntry> entries;
    	ZipEntry entry;
    	ArrayList<String> entryList = null;
    	byte[] buf = new byte[myThreadSafeData.getBufSize()];
    	String outFile;
		try {
			if (extractFolder == null || "".equals(extractFolder))
				extractFolder = ".";
			if (!extractFolder.endsWith("/") && !extractFolder.endsWith("\\"))
				extractFolder += File.separator;
			zipFile = new ZipFile(inFile);
	    	entries = zipFile.entries();
	    	while (entries.hasMoreElements()) {
	    		if (entryList == null)
		    		entryList = new ArrayList<String>();
	    		entry = entries.nextElement();
	    		outFile = extractFolder + entry.getName();
	    		entryList.add(outFile);
	    		bis = new BufferedInputStream(zipFile.getInputStream(entry));
	    		bos = new BufferedOutputStream(new FileOutputStream(new File(outFile)));
	    		while((len = bis.read(buf)) != -1)
	    			bos.write(buf, 0, len);
	    		bos.close(); bos = null;
	    		bis.close(); bis = null;
	    	}
	    	zipFile.close(); zipFile = null;
		} finally {
			if (bis != null) try{bis.close();}catch(Exception e) {}
			if (bos != null) try{bos.close();}catch(Exception e) {}
			if (zipFile != null) try{zipFile.close();}catch(Exception e) {}
		}
		logger.debug("<-- unzipFile()");
		return entryList;
	}

	protected synchronized String getIDESFileName(String folder, String senderGiin) throws Exception {
		logger.debug("--> getIDESFileName(). folder=" + folder + ", senderGiin=" + senderGiin);
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
			throw new Exception ("Unable to getIDESFileName() - file=" + file.getAbsolutePath());
		logger.debug("<-- getIDESFileName()");
		return outfile;
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
	
	protected boolean decrypt(String cipherTextFile, String encryptedAESKeyFile, String zippedSignedPlainTextFile, PrivateKey privkey) throws Exception {
		logger.debug("--> decrypt(). cipherTextFile= " + cipherTextFile + ", encryptedAESKeyFile=" + encryptedAESKeyFile + ", zippedSignedPlainTextFile=" + zippedSignedPlainTextFile);
		SecretKey skey;
		boolean ret = false;
		BufferedInputStream bis = null;
		byte[] buf, skeyBuf = null;
		int len, count;
		try {
			buf = new byte[myThreadSafeData.getBufSize()];
			bis = new BufferedInputStream(new FileInputStream(new File(encryptedAESKeyFile)));
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
		} finally {
			if (bis != null) try{bis.close();}catch(Exception e) {}
		}
		logger.debug("<-- decrypt()");
		return ret;
	}
	
	public ArrayList<String> unencryptZipPkg(String idesPkgFile, PrivateKey privateKey, boolean isApprover) throws Exception {
		return unencryptZipPkg(idesPkgFile, privateKey, isApprover, true);
	}
	
	public ArrayList<String> unencryptZipPkg(String idesPkgFile, PrivateKey privateKey, boolean isApprover, boolean isRenameZip) throws Exception {
		logger.debug("--> unencryptZipPkg(). idesPkg=" + idesPkgFile + ", isApprover=" + isApprover);
		boolean ret = false;
		String workingDir = new File(idesPkgFile).getAbsoluteFile().getParent();
		if (!"".equals(workingDir) && !workingDir.endsWith("/") && !workingDir.endsWith("\\"))
			workingDir += File.separator;
		ArrayList<String> entryList = unzipFile(idesPkgFile, workingDir);
		String approverKeyFile=null, receiverKeyFile=null, payloadFile=null, metadataFile=null, receiverGiin=null, senderGiin=null, filename;
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
		Unmarshaller unmrshlr = null;
		Object obj = null;
		unmrshlr = jaxbCtxMetadata1_0.createUnmarshaller();
		obj = unmrshlr.unmarshal(new File(metadataFile));;
		if (obj instanceof JAXBElement<?>) {
			@SuppressWarnings("unchecked")
			JAXBElement<fatca.idessenderfilemetadata.FATCAIDESSenderFileMetadataType> jaxbElem = 
				(JAXBElement<fatca.idessenderfilemetadata.FATCAIDESSenderFileMetadataType>)obj;
			fatca.idessenderfilemetadata.FATCAIDESSenderFileMetadataType metadataObj = jaxbElem.getValue();
			receiverGiin = metadataObj.getFATCAEntityReceiverId();
			senderGiin = metadataObj.getFATCAEntitySenderId();
		}
		if (approverKeyFile != null) {
			if (!receiverKeyFile.contains(receiverGiin)) {
				filename = approverKeyFile;
				approverKeyFile = receiverKeyFile;
				receiverKeyFile = filename;
			}
		}
		if (receiverGiin == null || senderGiin == null || receiverKeyFile == null)
			throw new Exception("Invalid metadata file - missing receiver or sender giin OR corrupt zip file - no reveiverKeyFile");
		if (isApprover && approverKeyFile == null)
			throw new Exception("Invalid package - no approverKeyFile");
		String zippedSignedPlainTextFile = UtilShared.getTmpFileName(workingDir, senderGiin, "Payload.zip");
		if (approverKeyFile != null && isApprover)
			ret = decrypt(payloadFile, approverKeyFile, zippedSignedPlainTextFile, privateKey);
		else
			ret = decrypt(payloadFile, receiverKeyFile, zippedSignedPlainTextFile, privateKey);
		file = new File(zippedSignedPlainTextFile);
		if (!ret) {
			if (file.exists()&&!file.delete())file.deleteOnExit();
			zippedSignedPlainTextFile = null;
		} else if (isRenameZip){
			tmp = workingDir + senderGiin + "_Payload.zip";
			File dest = new File(tmp);
			UtilShared.deleteDestAndRenameFile(file, dest);
			zippedSignedPlainTextFile = tmp;
		}
		if (zippedSignedPlainTextFile != null)
			entryList.add(zippedSignedPlainTextFile);
		entryList.remove(payloadFile);
		file = new File(payloadFile);
		if (file.exists()&&!file.delete())file.deleteOnExit();
		//file = new File(metadataFile);
		//if (file.exists()&&!file.delete())file.deleteOnExit();
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

	protected String createMetadata1_0(String folder, String senderGiin, String receiverGiin, int taxyear, String senderFileId, Date fileCreateTs) throws Exception {
		logger.debug("--> createMetadata1_0(). senderGiin=" + senderGiin + ", receiverGiin=" + receiverGiin + ", taxyear=" + taxyear + ", senderFileId=" + senderFileId + ", fileCreateTs=" + fileCreateTs);
		String metadatafile = UtilShared.getTmpFileName(folder, senderGiin, "Metadata.xml");
		JAXBContext jaxbCtxMetadata = JAXBContext.newInstance(fatca.idessenderfilemetadata.FATCAIDESSenderFileMetadataType.class);            
		Marshaller mrshler = jaxbCtxMetadata.createMarshaller();
		mrshler.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
		fatca.idessenderfilemetadata.FATCAIDESSenderFileMetadataType metadata = objFMetadata1_0.createFATCAIDESSenderFileMetadataType();
		JAXBElement<fatca.idessenderfilemetadata.FATCAIDESSenderFileMetadataType> jaxbElemMetadata = objFMetadata1_0.createFATCAIDESSenderFileMetadata(metadata);
		metadata.setFATCAEntCommunicationTypeCd(fatca.idessenderfilemetadata.FATCAEntCommunicationTypeCdType.RPT);
		metadata.setFATCAEntitySenderId(senderGiin);
		metadata.setFileRevisionInd(false);
		metadata.setSenderFileId(senderFileId);
		metadata.setTaxYear(genTaxYear(taxyear));
		metadata.setFATCAEntityReceiverId(receiverGiin);
		metadata.setFileCreateTs(sdfFileCreateTs.format(fileCreateTs));
		metadata.setSenderContactEmailAddressTxt(metadataEmailAddress);
		FileWriter fw = new FileWriter(new File(metadatafile));
		mrshler.marshal(jaxbElemMetadata, fw);
		fw.close();
		logger.debug("<-- createMetadata1_0()");
		return metadatafile;
	}
	
	protected String signAndCreatePkg(String unsignedXml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, String approverGiin, X509Certificate approvercert, int taxyear, 
			SigRefIdPos sigRefIdPos, SigXmlTransform xmlTransform, boolean isStreaming) throws Exception {
		logger.debug("--> signAndCreatePkg(). unsignedXml=" + unsignedXml + ", senderGiin=" + senderGiin + ", receiverGiin=" + receiverGiin + ", approverGiin=" + approverGiin + ", taxyear=" + taxyear + ", sigRefIdPos=" + sigRefIdPos + ", SigXmlTransform=" + xmlTransform + ", isStreaming=" + isStreaming);
		String signedxml = UtilShared.getTmpFileName(unsignedXml, "signed.xml");
		boolean success = false;
		String ret = null;
		if (isStreaming)
			success = myThreadSafeData.getSigner().signXmlFileStreaming(unsignedXml, signedxml, senderPrivateKey, senderPublicCert, sigRefIdPos, xmlTransform);
		else
			success = myThreadSafeData.getSigner().signXmlFile(unsignedXml, signedxml, senderPrivateKey, senderPublicCert, sigRefIdPos, xmlTransform);
		if (success)
			ret = createPkgWithApprover(signedxml, senderGiin, receiverGiin, receiverPublicCert, approverGiin, approvercert, taxyear);
		File f = new File(signedxml);
		if (f.exists() && !f.delete()) f.deleteOnExit();
		logger.debug("<-- signAndCreatePkg()");
		return ret;
	}
	
	public String signAndCreatePkgStreaming(String unsignedXml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, int taxyear, 
			SigRefIdPos sigRefIdPos, SigXmlTransform xmlTransform) throws Exception {
		String approverGiin = null;
		X509Certificate approverPublicCert = null;
		boolean isStreaming = true;
		if (sigRefIdPos == null)
			sigRefIdPos = SigRefIdPos.Object;
		if (xmlTransform == null)
			xmlTransform = SigXmlTransform.Inclusive;
		return signAndCreatePkg(unsignedXml, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, receiverPublicCert, 
				approverGiin, approverPublicCert, taxyear, sigRefIdPos, xmlTransform, isStreaming);
	}
	
	public String signAndCreatePkgStreaming(String unsignedXml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, int taxyear) throws Exception {
		return signAndCreatePkgStreaming(unsignedXml, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
				receiverPublicCert, taxyear, SigRefIdPos.Object, SigXmlTransform.Inclusive);
	}
	
	public String signAndCreatePkgWithApproverStreaming(String unsignedXml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, String approverGiin, X509Certificate approvercert, int taxyear,
			SigRefIdPos sigRefIdPos) throws Exception {
		SigXmlTransform xmlTransform = SigXmlTransform.Inclusive;
		boolean isStreaming = true;
		if (sigRefIdPos == null)
			sigRefIdPos = SigRefIdPos.Object;
		return signAndCreatePkg(unsignedXml, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, receiverPublicCert, approverGiin, approvercert, taxyear, sigRefIdPos, xmlTransform, isStreaming);
	}
	
	public String signAndCreatePkgWithApproverStreaming(String unsignedXml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, String approverGiin, X509Certificate approvercert, int taxyear) throws Exception {
		return signAndCreatePkgWithApproverStreaming(unsignedXml, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
			receiverPublicCert, approverGiin, approvercert, taxyear, SigRefIdPos.Object);
	}
	
	public String signAndCreatePkg(String unsignedXml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, int taxyear, 
			SigRefIdPos sigRefIdPos, SigXmlTransform xmlTransform) throws Exception {
		String approverGiin = null;
		X509Certificate approverPublicCert = null;
		boolean isStreaming = false;
		if (sigRefIdPos == null)
			sigRefIdPos = SigRefIdPos.Object;
		if (xmlTransform == null)
			xmlTransform = SigXmlTransform.Inclusive;
		return signAndCreatePkg(unsignedXml, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, receiverPublicCert, approverGiin, approverPublicCert, taxyear, sigRefIdPos, xmlTransform, isStreaming);
	}
	
	public String signAndCreatePkgWithApprover(String unsignedXml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, String approverGiin, X509Certificate approvercert, int taxyear,
			SigRefIdPos sigRefIdPos, SigXmlTransform xmlTransform) throws Exception {
		boolean isStreaming = false;
		if (sigRefIdPos == null)
			sigRefIdPos = SigRefIdPos.Object;
		if (xmlTransform == null)
			xmlTransform = SigXmlTransform.Inclusive;
		return signAndCreatePkg(unsignedXml, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, receiverPublicCert, 
				approverGiin, approvercert, taxyear, sigRefIdPos, xmlTransform, isStreaming);
	}
	
	public void createZipPkg(String signedXmlFile, String senderGiin, String xmlzipFilename) throws Exception {
		logger.debug("--> createZipPkg(). signedXmlFile= " + signedXmlFile + ", senderGiin=" + senderGiin  + ", xmlzipFilename=" + xmlzipFilename);
		boolean success = false;
		String folder = new File(signedXmlFile).getAbsoluteFile().getParent();
		if (xmlzipFilename == null)
			xmlzipFilename = UtilShared.getTmpFileName(folder, senderGiin, "Payload.zip");
		success = createZipFile(new String[]{signedXmlFile}, xmlzipFilename);
		if (success)
			success = renameZipEntry(xmlzipFilename, getFileName(signedXmlFile), senderGiin + "_Payload.xml");
		if (!success)
			throw new Exception("uanble to create " + xmlzipFilename);
		logger.debug("<-- createZipPkg()");
	}
	
	public String createPkg(String signedXmlFile, String senderGiin, String receiverGiin,  
			X509Certificate receiverPublicCert, int taxyear) throws Exception {
		return createPkgWithApprover(signedXmlFile, senderGiin, receiverGiin, receiverPublicCert, null, null, taxyear);
	}
	
	public String createPkgWithApprover(String signedXmlFile, String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, 
			String approverGiin, X509Certificate approvercert, int taxyear) throws Exception {
		logger.debug("--> createPkgWithApprover(). signedXmlFile= " + signedXmlFile + ", senderGiin=" + senderGiin + ", receiverGiin=" + receiverGiin + ", approverGiin=" + approverGiin);
		String folder = new File(signedXmlFile).getAbsoluteFile().getParent();
		String xmlzipFilename = UtilShared.getTmpFileName(folder, senderGiin, "Payload.zip");
		createZipPkg(signedXmlFile, senderGiin, xmlzipFilename);
		String idesOutFile = encryptZipPkg(xmlzipFilename, senderGiin, receiverGiin, receiverPublicCert, 
				approverGiin, approvercert, taxyear);
		File file = new File(xmlzipFilename);
		if (file.exists()&&!file.delete())file.deleteOnExit();
		logger.debug("<-- createPkgWithApprover()");
		return idesOutFile;
	}

	public ArrayList<String> unpack(String idesPkgFile, String keystoreType, String keystoreFile, String keystorePwd, String keyPwd, String keyAlias) throws Exception {
		logger.debug("--> unpack(). idesPkgFile=" + idesPkgFile + ", keystoreType=" + keystoreType + ", keystoreFile=" + keystoreFile + ", keyAlias=" + keyAlias);
		PrivateKey privateKey = UtilShared.getPrivateKey(keystoreType, keystoreFile, keystorePwd, keyPwd, keyAlias);
		ArrayList<String> ret = unpack(idesPkgFile, privateKey);
		logger.debug("<-- unpack()");
		return ret;
	}
	
	public ArrayList<String> unpack(String idesPkgFile, PrivateKey receiverPrivateKey) throws Exception {
		logger.debug("--> unpack(). idesPkgFile=" + idesPkgFile);
		boolean isApprover = false;
		ArrayList<String> ret = unpack(idesPkgFile, receiverPrivateKey, isApprover);
		logger.debug("<-- unpack()");
		return ret;
	}
	
	public ArrayList<String> unpackForApprover(String idesPkgFile, String approverKeystoreType, String approverKeystoreFile, 
			String approverKeystorePwd, String approverKeyPwd, String approverKeyAlias) throws Exception {
		logger.debug("--> unpackForApprover(). idesPkgFile=" + idesPkgFile + ", approverKeystoreType=" + approverKeystoreType + ", approverKeystoreFile=" + approverKeystoreFile + ", approverKeyAlias=" + approverKeyAlias);
		PrivateKey approverPrivateKey = UtilShared.getPrivateKey(approverKeystoreType, approverKeystoreFile, approverKeystorePwd, approverKeyPwd, approverKeyAlias);
		ArrayList<String> ret = unpackForApprover(idesPkgFile, approverPrivateKey);
		logger.debug("<-- unpackForApprover()");
		return ret;
	}
	
	public ArrayList<String> unpackForApprover(String idesPkgFile, PrivateKey approverPrivateKey) throws Exception {
		logger.debug("--> unpackForApprover(). idesPkgFile=" + idesPkgFile);
		ArrayList<String> ret = unpack(idesPkgFile, approverPrivateKey, true);
		logger.debug("<-- unpackForApprover()");
		return ret;
	}

	public String encryptZipPkg(String xmlzipFilename, String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, 
			String approverGiin, X509Certificate approverPublicCert, int taxyear) throws Exception {
		logger.debug("--> encryptZipPkg(). xmlzipFilename= " + xmlzipFilename + ", senderGiin=" + senderGiin + ", receiverGiin=" + receiverGiin + ", approverGiin=" + approverGiin + ", taxyear=" + taxyear);
		boolean success = false;
		String folder = new File(xmlzipFilename).getAbsoluteFile().getParent();
		Date date = new Date();
		String idesOutFile = getIDESFileName(folder, senderGiin);
		File file = new File(idesOutFile);
		String senderFileId = file.getName();
		String metadatafile = null;
		metadatafile = createMetadata1_0(folder, senderGiin, receiverGiin, taxyear, senderFileId, date);
		Certificate[] certs = null;
		String[] encryptedAESKeyOutFiles = null;
		if (approverPublicCert != null && approverGiin != null) {
			certs = new X509Certificate[] {receiverPublicCert, approverPublicCert};
			encryptedAESKeyOutFiles = new String[]{UtilShared.getTmpFileName(folder, receiverGiin, "Key"), UtilShared.getTmpFileName(folder, approverGiin, "Key")};
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
			if (file.exists()&&!file.delete())file.deleteOnExit();
		}
		logger.debug("<-- encryptZipPkg()");
		return idesOutFile;
	}
	
	// for backward compatibility
	public static boolean isCanonicalization = true;
	public String signAndCreatePkg(String unsignedXml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, int taxyear) throws Exception {
		String approverGiin = null;
		X509Certificate approverPublicCert = null;
		return signAndCreatePkgWithApprover(unsignedXml, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, receiverPublicCert, approverGiin, approverPublicCert, taxyear);
	}
	
	// for backward compatibility
	public String signAndCreatePkgWithApprover(String unsignedXml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, String approverGiin, X509Certificate approvercert, int taxyear) throws Exception {
		boolean isStreaming = true;
		SigXmlTransform xmlTransform;
		if (isCanonicalization)
			xmlTransform = SigXmlTransform.Inclusive;
		else
			xmlTransform = SigXmlTransform.None;
		return signAndCreatePkg(unsignedXml, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, receiverPublicCert, approverGiin, approvercert, 
				taxyear, SigRefIdPos.Object, xmlTransform, isStreaming);
	}

    public void setBufSize(int val) {
    	myThreadSafeData.setBufSize(val);
	}

    public int getBufSize() {
    	return myThreadSafeData.getBufSize();
	}

	public FATCAXmlSigner getSigner() {
		return myThreadSafeData.getSigner();
	}

	public void setSigner(FATCAXmlSigner val) {
		myThreadSafeData.setSigner(val);
	}
}
