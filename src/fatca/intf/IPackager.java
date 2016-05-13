package fatca.intf;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

/*
 * @author	Subir Paul (IT:ES:SE:PE)
 * 
 */
public interface IPackager extends IPackagerExtra {
	public enum AesCipherOpMode {CBC, ECB};
	public enum MetadataFileFormat {XML, TXT, JPG, PDF, RTF};
	public enum MetadataBinaryEncoding {NONE, BASE_64};
	public String defaultKeystoreType = "pkcs12";
	public String certificateType = "X.509";
	public int maxAttemptsToCreateNewFile = 10;
	
	//AES Cipher operation mode - either ECB or CBC
	public void setAesCipherOpMode(String aesCipherOpMode) throws Exception;
    public String getAesCipherOpMode();

	//this method signs an XML using streaming api (to calculate signature digest) and creates IDES pkg
	public String signAndCreatePkgStreaming(String unsignedXml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, int taxyear) throws Exception;
	
	//this method signs an XML using signature DOM api and creates IDES pkg - as DOM reads entire XML in memory, XML file size is restricted by heap 
	public String signAndCreatePkg(String unsignedXml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, int taxyear) throws Exception;
	
	//this method creates IDES pkg 
	public String createPkg(String signedXmlFile, String senderGiin, String receiverGiin,  
			X509Certificate receiverPublicCert, int taxyear) throws Exception;
	
	//this method unpack an IDES pkg 
	public ArrayList<String> unpack(String idesPkgFile, String keystoreType, String keystoreFile, String keystorePwd, String keyPwd, 
			String keyAlias) throws Exception;
	
	//this method unpack an IDES pkg 
	public ArrayList<String> unpack(String idesPkgFile, PrivateKey receiverPrivateKey) throws Exception;
	
	//this method wraps base64 binary in xml, signs and creates IDES pkg 
	public String signBinaryFileAndCreatePkgStreaming(String unsignedBinaryDoc, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, int taxyear, MetadataFileFormat fileFormat) throws Exception;

	//this method wraps base64 binary in xml, signs and creates IDES pkg 
	public String signBinaryFileAndCreatePkg(String unsignedBinaryDoc, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, int taxyear, MetadataFileFormat fileFormat) throws Exception;
	
	//this method wraps text in xml, signs and creates IDES pkg 
	public String signTextFileAndCreatePkgStreaming(String unsignedText, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, int taxyear) throws Exception;

	//this method wraps text in xml, signs and creates IDES pkg 
	public String signTextFileAndCreatePkg(String unsignedText, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, int taxyear) throws Exception;

	//default buffer size is 8192
	public void setBufSize(int val);
    public int getBufSize();

	//embedded IFATCAXmlSignerExtended
    public ISigner getSigner();
	public void setSigner(ISigner val);

	//this method takes zipped signed xml payload and creates IDES pkg 
	public String encryptZipPkg(String xmlzipFilename, String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, 
			String approverGiin, X509Certificate approverPublicCert, int taxyear, 
			MetadataFileFormat fileFormat, MetadataBinaryEncoding binaryEncoding) throws Exception;

	//this method signs an XML using streaming api (to calculate signature digest) and creates IDES pkg for approver - model1 option2 
	public String signAndCreatePkgWithApproverStreaming(String unsignedXml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, String approverGiin, X509Certificate approverPublicCert, 
			int taxyear) throws Exception;
	
	//this method signs an XML using signature DOM api and creates IDES pkg for approver - model1 option2 - as DOM reads entire XML in memory, XML file size is restricted by heap 
	public String signAndCreatePkgWithApprover(String unsignedXml, PrivateKey senderPrivateKey, X509Certificate senderPublicCert,
			String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, String approverGiin, X509Certificate approverPublicCert, 
			int taxyear) throws Exception;

	//this method creates IDES pkg for approver - model1 option2 
	public String createPkgWithApprover(String signedXmlFile, String senderGiin, String receiverGiin, X509Certificate receiverPublicCert, 
			String approverGiin, X509Certificate approverPublicCert, int taxyear) throws Exception;
	
	//this method unpack an IDES pkg for approver - model1 option2 
	public ArrayList<String> unpackForApprover(String idesPkgFile, String approverKeystoreType, String approverKeystoreFile, 
			String approverKeystorePwd, String approverKeyPwd, String approverKeyAlias) throws Exception;
	
	//this method unpack an IDES pkg for approver - model1 option2 
	public ArrayList<String> unpackForApprover(String idesPkgFile, PrivateKey approverPrivateKey) throws Exception;
}
