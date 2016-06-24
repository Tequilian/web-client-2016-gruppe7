package com.web;

public class User {

	private int user_id;
	private String created_at;
	private String identity;
	private String privkey_user_enc;
	private String pubkey_user;
	private String salt_masterkey;
	private String updated_at;
	
	
	public int getUser_id() {
		return user_id;
	}

	public String getCreated_at() {
		return created_at;
	}
	public void setCreated_at(String created_at) {
		this.created_at = created_at;
	}
	public String getIdentity() {
		return identity;
	}
	public void setIdentity(String identity) {
		this.identity = identity;
	}
	public String getPrivkey_user_enc() {
		return privkey_user_enc;
	}
	public void setPrivkey_user_enc(String privkey_user_enc) {
		this.privkey_user_enc = privkey_user_enc;
	}
	public String getPubkey_user() {
		return pubkey_user;
	}
	public void setPubkey_user(String pubkey_user) {
		this.pubkey_user = pubkey_user;
	}
	public String getSalt_masterkey() {
		return salt_masterkey;
	}
	public void setSalt_masterkey(String salt_masterkey) {
		this.salt_masterkey = salt_masterkey;
	}
	public String getUpdated_at() {
		return updated_at;
	}
	public void setUpdated_at(String updated_at) {
		this.updated_at = updated_at;
	}
}
