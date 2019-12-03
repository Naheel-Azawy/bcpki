pragma solidity >=0.4.21 <0.6.0;
pragma experimental ABIEncoderV2;

import "./Ownable.sol";

contract CA is Ownable {

  uint constant VERSION = 1;

  struct X509 {
    uint    version;
    string  algor_ident;
    string  valid_to;
    string  subject_name;
    string  public_key;
    address issuer_id;
    string  subject_id;
    string  signature;
    bool    exist;
    address wallet_owner;
  }

  // Certificates, referenced by cert hash
  mapping(string => X509) certs;
  mapping(uint => string) certs_map;
  uint certs_count;

  // Certificate Revocation List, referenced by cert hash
  mapping(string => bool) crl;
  mapping(uint => string) crl_map;
  uint crl_count;

  // Tiny hack to make solidity work...
  X509 NULL;

  constructor() public {
    certs_count = 0;
  }
  /* event verLog(
    string s
  ); */

  function enroll(string memory cert_hash,
                  string memory algor_ident,
                  string memory valid_to,
                  string memory subject_name,
                  string memory public_key,
                  string memory subject_id,
                  string memory signature)
    public returns(bool) {
    if (certs[cert_hash].exist) {
      return false;
    } else {
      X509 memory c = X509(VERSION, algor_ident, valid_to, subject_name, public_key, owner, subject_id, signature, true, msg.sender);
      certs[cert_hash] = c;
      crl[cert_hash] = false;
      certs_map[certs_count] = cert_hash;
      ++certs_count;
      return true;
    }
  }

  function revoke(string memory cert_hash)
    public onlyOwner {
    crl[cert_hash] = true;
    crl_map[crl_count] = cert_hash;
    ++crl_count;
  }

  function verify(string memory cert_hash)
    public view returns(bool) {
    /* emit verLog(cert_hash); */
    if (msg.sender == get_cert(cert_hash).wallet_owner){
      return true;
    } else {
      return false;
    }
    //return true;
  }

  function get_full_cert(string memory cert_hash)
    public view returns(X509 memory) {
    /* emit verLog(cert_hash); */
    if (msg.sender == get_cert(cert_hash).wallet_owner){
      return certs[cert_hash];
    } else {
      return NULL;
    }
    //return true;
  }

  function get_certs_count()
    public view returns(uint) {
    return certs_count;
  }

  function get_cert_hash(uint index)
    public view returns(string memory) {
    return certs_map[index];
  }

  function get_crl_count()
    public view returns(uint) {
    return crl_count;
  }

  function get_revoked_cert_hash(uint index)
    public view returns(string memory) {
    return crl_map[index];
  }

  function get_cert(string memory cert_hash)
    private view returns(X509 memory) {
    if (!certs[cert_hash].exist) {
      return NULL;
    } else {
      return certs[cert_hash];
    }
  }

  function get_cert_version(string memory cert_hash)
    public view returns(uint) {
    return get_cert(cert_hash).version;
  }

  function get_cert_algor_ident(string memory cert_hash)
    public view returns(string memory) {
    return get_cert(cert_hash).algor_ident;
  }

  function get_cert_valid_to(string memory cert_hash)
    public view returns(string memory) {
    return get_cert(cert_hash).valid_to;
  }

  function get_cert_subject_name(string memory cert_hash)
    public view returns(string memory) {
    return get_cert(cert_hash).subject_name;
  }

  function get_cert_public_key(string memory cert_hash)
    public view returns(string memory) {
    return get_cert(cert_hash).public_key;
  }

  function get_cert_issuer_id(string memory cert_hash)
    public view returns(address) {
    return get_cert(cert_hash).issuer_id;
  }

  function get_cert_subject_id(string memory cert_hash)
    public view returns(string memory) {
    return get_cert(cert_hash).subject_id;
  }

  function get_cert_signature(string memory cert_hash)
    public view returns(string memory) {
    return get_cert(cert_hash).signature;
  }

  function get_cert_exist(string memory cert_hash)
    public view returns(bool) {
    return get_cert(cert_hash).exist;
  }

  // for debugging -------------------------------------

  function get_crl()
    public view returns(X509[] memory) {
    X509[] memory list = new X509[](crl_count);
    for (uint i = 0; i < crl_count; ++i) {
      list[i] = certs[crl_map[i]];
    }
    return list;
  }

  function get_certs()
    public view returns(X509[] memory) {
    X509[] memory list = new X509[](certs_count - crl_count);
    for (uint i = 0; i < certs_count; ++i) {
      if (!crl[certs_map[i]])
        list[i] = certs[certs_map[i]];
    }
    return list;
  }

  function get_all_certs()
    public view returns(X509[] memory) {
    X509[] memory list = new X509[](certs_count);
    for (uint i = 0; i < certs_count; ++i) {
      list[i] = certs[certs_map[i]];
    }
    return list;
  }

}
