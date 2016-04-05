package fatca.intf;

import java.security.PrivateKey;
import java.util.ArrayList;

/*
 * @author	Subir Paul (IT:ES:SE:PE)
 * 
 */
public interface IPackagerExtra {
	//this method creates ZIP pkg - senderGiin_Payload.zip
	public void createZipPkg(String signedXmlFile, String senderGiin, String outputZipFilename) throws Exception;
	
	public boolean createZipFile(String[] inFiles, String outFile) throws Exception;
	
	public ArrayList<String> unzipFile(String inFile) throws Exception;
	public ArrayList<String> unzipFile(String inFile, String extractFolder) throws Exception;
	
	public ArrayList<String> unencryptZipPkg(String idesPkgFile, PrivateKey privateKey, boolean isApprover) throws Exception;

	//flag indicating if decryption automatically considers 48 byte key size as CBC (32 byte key + 16 byte IV) and 32 bytes key as ECB cipher mode
	public boolean isDualModeDecryption();
	public void setDualModeDecryption(boolean flag);
}
