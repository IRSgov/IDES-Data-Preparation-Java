package fatca.intf;

/*
 * @author	Subir Paul (IT:ES:SE:PE)
 * 
 */
public interface ISignerExtra {
	//No prefix - <Signature xmlns="http://www.w3.org/2000/09/xmldsig#" ...>
	//With prefix 'dsig' - <dsig:Signature xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" ...> 
    public String getSignaturePrefix();
    public void setSignaturePrefix(String prefix);

	//flag XmlChunkStreaming - default to true
	public boolean isXmlChunkStreaming();
	public void setXmlChunkStreaming(boolean flag);
	
	//chunk size if XmlChunkStreaming is true - default is 8092. XmlChunk is used with streaming based signing to calculate message digest
	public int getXmlChunkStreamingSize();
	public void setXmlChunkStreamingSize(int val);

	//following methods are for debug only - works with small file only
	public StringBuilder getDigestBuf();
	public void setDigestBuf(StringBuilder digestBuf);
	public void setValidationSuccess(Boolean isValidationSuccess);
	public void setValidateAllSignature(boolean isValidateAllSignature);
	public boolean isValidateAllSignature();
	public Boolean isValidationSuccess();
}
