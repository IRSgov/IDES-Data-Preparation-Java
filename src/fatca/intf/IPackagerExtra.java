package fatca.intf;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Date;

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

	public String createMetadata1_0(String folder, String senderGiin, String receiverGiin, int taxyear, String senderFileId, Date fileCreateTs) throws Exception;
	public String createMetadata1_1(String folder, String senderGiin, String receiverGiin, int taxyear, 
			String senderFileId, Date fileCreateTs, fatca.idessenderfilemetadata1_1.FileFormatCdType fileFormatCd, 
			fatca.idessenderfilemetadata1_1.BinaryEncodingSchemeCdType binaryEncodingCd) throws Exception;
	public boolean renameZipEntries(String zipFile, String[] entryNames, String[] newEntryNames) throws Exception;
	public void setMetadataVer(float metadataVer);
	
	public void setKeepSignedXmlAfterSignAndCreatePkgFlag(boolean flag);
	public boolean getKeepSignedXmlAfterSignAndCreatePkgFlag();
}
