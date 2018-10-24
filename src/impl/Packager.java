package impl;


import intf.ISigner;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.text.SimpleDateFormat;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.TimeZone;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;

import util.UtilShared;

/*
 * @author	Subir Paul (OS:IT:ES:EST:PA:S1)
 * 
 */
public class Packager {
	protected final String RSA_TRANSFORMATION = "RSA";
	protected final String SECRET_KEY_ALGO = "AES";
	protected final int SECRET_KEY_SIZE_IN_BITS = 256;

	protected final String AesTransformationCBC = "AES/CBC/PKCS5Padding";
	
	protected Logger logger = Logger.getLogger(new Object(){}.getClass().getEnclosingClass().getName());

	protected SimpleDateFormat sdfFileName = new SimpleDateFormat("yyyyMMdd'T'HHmmssSSS'Z'");
	
	//for debug only
	protected boolean keepSignedXmlAfterSignAndCreatePkgFlag = false;
	
	protected ISigner signer = null;
	
	public Packager() {
		sdfFileName.setTimeZone(TimeZone.getTimeZone(ZoneOffset.UTC));
	}
		
	//AES encrypt or decrypt. For CBC decryption, secretKey must be 32 byte aes key + 16 byte IV 
	//48 bytes key size (32 bytes aes key + 16 bytes IV) = CBC 
	protected Cipher aes(int opmode, String inputFile, String outputFile, SecretKey secretKey) throws Exception {
		logger.debug("--> aes(). opmode=" + (opmode==Cipher.ENCRYPT_MODE?"ENCRYPT":"DECRYPT") + ", inputFile=" + inputFile + ", outputFile=" + outputFile);
		if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE)
			throw new Exception("Invalid opmode " + opmode + ". Allowed opmodes are Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE");
		Cipher ret = null;
		BufferedInputStream bis = null;
		BufferedOutputStream bos = null;
		int len;
		byte[] output = null;
		byte[] buf = new byte[UtilShared.defaultBufSize];
		Cipher cipher;
		IvParameterSpec iv = null;
		try {
			byte[] ivBuf = null;
			if (opmode == Cipher.DECRYPT_MODE) {
				byte[] skeyBuf = null, skeyIvBuf = secretKey.getEncoded();
				int expectedSKeySizeInBytes = SECRET_KEY_SIZE_IN_BITS/8; 
				if (skeyIvBuf.length > expectedSKeySizeInBytes) {
					//IV is appended to aes key, separate them
					skeyBuf = new byte[expectedSKeySizeInBytes];
					ivBuf = new byte[skeyIvBuf.length - skeyBuf.length];
					System.arraycopy(skeyIvBuf, 0, skeyBuf, 0, skeyBuf.length);
					System.arraycopy(skeyIvBuf, skeyBuf.length, ivBuf, 0, ivBuf.length);
					if (ivBuf.length != 16)
						throw new Exception("incorrect IV size - " + ivBuf.length + " bytes");
					if (skeyBuf.length != expectedSKeySizeInBytes)
						throw new Exception("incorrect KEY size - " + skeyBuf.length + " bytes");
					secretKey = new SecretKeySpec(skeyBuf, SECRET_KEY_ALGO);
					iv = new IvParameterSpec(ivBuf);
				}
				if (iv == null)
					throw new Exception("invalid KEY size - missing IV");
			} /*else if (opmode == Cipher.ENCRYPT_MODE) {
				//CBC encryption. This block is not required as JDK creates IV and uses automatically for CBC for encryption
				ivBuf = new byte[16];
				new SecureRandom().nextBytes(ivBuf);
				iv = new IvParameterSpec(ivBuf);
			}*/
			cipher = Cipher.getInstance(AesTransformationCBC);
			cipher.init(opmode, secretKey, iv);
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
			ret = cipher;
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
	
	//Generates 32 bytes aes key, invokes aes() method for encryption, for CBC cipher mode, append IV (16 bytes) with aes key(32 bytes), 
	//wrap/encrypt secret key using receivers PKI public key - secret key size is 48 bytes (CBC) aes key+iv    
	protected boolean encrypt(String zippedSignedPlainTextFile, String cipherTextOutFile, PublicKey[] receiversPublicKey,
			String[] encryptedAESKeyOutFiles) throws Exception {
		logger.debug("--> encrypt(). zippedSignedPlainTextFile=" + zippedSignedPlainTextFile + ", cipherTextOutFile" + cipherTextOutFile);
		boolean ret = false;
		SecretKey skey = null;
		KeyGenerator generator;
		byte[] encryptedAESKeyBuf;
		BufferedOutputStream bos = null;
		byte[] ivBuf = null;
		try {
			generator = KeyGenerator.getInstance(SECRET_KEY_ALGO);
			generator.init(SECRET_KEY_SIZE_IN_BITS);
			skey = generator.generateKey();
			byte[] skeyBuf = skey.getEncoded();
			Cipher aesCipher = aes(Cipher.ENCRYPT_MODE, zippedSignedPlainTextFile, cipherTextOutFile, skey);
			if (aesCipher != null) {
				ivBuf = aesCipher.getIV();
				for (int i = 0; i < receiversPublicKey.length && i < encryptedAESKeyOutFiles.length; i++) {
					//wrap/encrypt secret key using receivers PKI public key -
					//secret key size is 48 bytes (CBC) aes key+iv
					Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
					cipher.init(Cipher.WRAP_MODE, receiversPublicKey[i]);
					if (ivBuf != null) {
						//append 16 bytes IV to 32 bytes aes SecretKey buffer and create 48 bytes SecretKey
						byte[] skeyPlusIvBuf = new byte[skeyBuf.length + ivBuf.length];
						System.arraycopy(skeyBuf, 0, skeyPlusIvBuf, 0, skeyBuf.length);
						System.arraycopy(ivBuf, 0, skeyPlusIvBuf, skeyBuf.length, ivBuf.length);
						logger.debug("key buf size=" + skeyPlusIvBuf.length);
						skey = new SecretKeySpec(skeyPlusIvBuf, SECRET_KEY_ALGO);;
					}
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

	// JRE 7 or up
	protected boolean renameZipEntry(String zipFile, String entryName, String newEntryName) throws Exception {
		logger.debug("--> renameZipEntry(). zipFile=" + zipFile + ", entryName=" + entryName + ", newEntryName=" + newEntryName);
		boolean ret = false;
        HashMap<String, String> props = new HashMap<String, String>(); 
        props.put("create", "false"); 
        URI zipDisk = URI.create("jar:" + new File(zipFile).toURI());
        FileSystem zipfs = FileSystems.newFileSystem(zipDisk, props);
        Path pathInZipfile = zipfs.getPath(entryName);
        Path renamedZipEntry = zipfs.getPath(newEntryName);
        Files.move(pathInZipfile, renamedZipEntry, StandardCopyOption.ATOMIC_MOVE);
        zipfs.close();
        ret = true;
		logger.debug("<-- renameZipEntry()");
		return ret;
	}
	
	public boolean renameZipEntries(String zipFile, String[] entryNames, String[] newEntryNames) throws Exception {
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
        HashMap<String, String> props = new HashMap<String, String>(); 
        props.put("create", "false"); 
        URI zipDisk = URI.create("jar:" + new File(zipFile).toURI());
    	FileSystem zipfs = FileSystems.newFileSystem(zipDisk, props);
    	Path pathInZipfile, renamedZipEntry;
    	for (int i = 0; i < entryNames.length; i++) {
            pathInZipfile = zipfs.getPath(entryNames[i]);
            renamedZipEntry = zipfs.getPath(newEntryNames[i]);
            Files.move(pathInZipfile, renamedZipEntry, StandardCopyOption.ATOMIC_MOVE);
    	}
        zipfs.close();
        ret = true;
		logger.debug("<-- renameZipEntries()");
		return ret;
	}
	
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
		byte[] buf = new byte[UtilShared.defaultBufSize];
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

	/*
	// for JRE 6. If you have JRE 7 or up use JRE 7 or up version
	//renames an entry within zip file
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
	
	//renames multiple entries within zip file
	public boolean renameZipEntries(String zipFile, String[] entryNames, String[] newEntryNames) throws Exception {
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
	*/

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
    	byte[] buf = new byte[UtilShared.defaultBufSize];
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

	protected String getFileName(String filename) {
		File f = new File(filename);
		return f.getName();
	}
	
	//read key file into a buffer, unwrap/decrypt encrypted aes secret keykey using receiver's/own PKI private key, use aes key and decrypt payload
	protected boolean decrypt(String cipherTextFile, String encryptedAESKeyFile, String zippedSignedPlainTextFile, PrivateKey privkey) throws Exception {
		logger.debug("--> decrypt(). cipherTextFile= " + cipherTextFile + ", encryptedAESKeyFile=" + encryptedAESKeyFile + ", zippedSignedPlainTextFile=" + zippedSignedPlainTextFile);
		SecretKey skey;
		boolean ret = false;
		BufferedInputStream bis = null;
		byte[] buf, skeyBuf = null;
		int len, count;
		try {
			buf = new byte[UtilShared.defaultBufSize];
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
			ret = aes(Cipher.DECRYPT_MODE, cipherTextFile, zippedSignedPlainTextFile, skey) != null ? true : false;
		} finally {
			if (bis != null) try{bis.close();}catch(Exception e) {}
		}
		logger.debug("<-- decrypt()");
		return ret;
	}
	
	//this method creates ZIP pkg 
	public void createZipPkg(String signedXmlFile, String filePrefix, String outputZipFilename) throws Exception {
		logger.debug("--> createZipPkg(). signedXmlFile= " + signedXmlFile + ", filePrefix=" + filePrefix  + 
				", outputZipFilename=" + outputZipFilename);
		boolean success = false;
		String folder = new File(signedXmlFile).getAbsoluteFile().getParent();
		if (outputZipFilename == null)
			outputZipFilename = UtilShared.getTmpFileName(folder, filePrefix, "Payload.zip");
		success = createZipFile(new String[]{signedXmlFile}, outputZipFilename);
		if (success)
			success = renameZipEntry(outputZipFilename, getFileName(signedXmlFile), filePrefix + "_Payload.xml");
		if (!success)
			throw new Exception("uanble to create " + outputZipFilename);
		logger.debug("<-- createZipPkg()");
	}
	
	//embedded ISigner
	public ISigner getSigner() {
		return signer;
	}

	public void setSigner(ISigner val) {
		signer = val;
	}

	public void setKeepSignedXmlAfterSignAndCreatePkgFlag(boolean flag) {
		this.keepSignedXmlAfterSignAndCreatePkgFlag = flag;
	}

	public boolean getKeepSignedXmlAfterSignAndCreatePkgFlag() {
		return keepSignedXmlAfterSignAndCreatePkgFlag;
	}

    public void setProperty(String prop, Object value) {
    	if ("keepSignedXmlAfterSignAndCreatePkgFlag".equalsIgnoreCase(prop))
    		keepSignedXmlAfterSignAndCreatePkgFlag = (Boolean)value; 
	}
    
    public Object getProperty(String prop) {
    	if ("keepSignedXmlAfterSignAndCreatePkgFlag".equalsIgnoreCase(prop))
    		return keepSignedXmlAfterSignAndCreatePkgFlag; 
		return null;
    }
}
