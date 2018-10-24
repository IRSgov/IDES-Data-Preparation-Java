package intf;

import java.util.Date;
import java.util.HashMap;

/*
 * @author	Subir Paul (OS:IT:ES:EST:PA:S1)
 * 
 */
public interface IMetadata {
	public void setMetadataInfo(String emailAddress, String fileRevisionId, String origTranId);
	public String createMetadata(String folder, String senderGiin, String receiverGiin, String commType, 
			String senderFileId, String fileFormat, String binaryEncoding, Date fileCreateTs, int taxyear) throws Exception;
	public HashMap<String, String> getMetadataInfo(String metadataFile) throws Exception;
	public String getSenderId(HashMap<String, String> map);
	public String getReceiverId(HashMap<String, String> map);
	public String getCommTypeCd(HashMap<String, String> map);
	public Object unmarshal(String metadataFile) throws Exception;
}
