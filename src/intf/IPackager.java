package intf;

import java.security.PrivateKey;
import java.util.ArrayList;

/*
 * @author	Subir Paul (OS:IT:ES:EST:PA:S1)
 * 
 */
public interface IPackager {
	public void createZipPkg(String signedXmlFile, String filePrefix, String outputZipFilename) throws Exception;
	
	public boolean createZipFile(String[] inFiles, String outFile) throws Exception;
	
	public ArrayList<String> unzipFile(String inFile) throws Exception;
	public ArrayList<String> unzipFile(String inFile, String extractFolder) throws Exception;
	
	public void setMetadataInfo(String email, String fileRevisionId, String origTranId);

	public boolean renameZipEntries(String zipFile, String[] entryNames, String[] newEntryNames) throws Exception;

	//this method unpack an pkg 
	public ArrayList<String> unpack(String pkgFile, String keystoreType, String keystoreFile, String keystorePwd, String keyPwd, 
			String keyAlias) throws Exception;
	
	//this method unpack an pkg 
	public ArrayList<String> unpack(String pkgFile, PrivateKey receiverPrivateKey) throws Exception;
	
    public ISigner getSigner();
	public void setSigner(ISigner val);

	public void setProperty(String prop, Object value);
    public Object getProperty(String prop);

	public IMetadata getMetadata();
	public void setMetadata(IMetadata metadata);
}
