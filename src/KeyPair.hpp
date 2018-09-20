namespace SkyCryptor {

template<class POINT_TYPE, class NUMBER_TYPE>
KeyPair::KeyPair(const PrivateKey<NUMBER_TYPE>& privateKey)
    : privateKey(privateKey)
    , publicKey(privateKey.get_publicKey())
{

}

template<class POINT_TYPE, class NUMBER_TYPE>
KeyPair::KeyPair(const PrivateKey<NUMBER_TYPE>& privateKey, 
                 const PublicKey<POINT_TYPE, NUMBER_TYPE>& publicKey) 
    : privateKey(privateKey)
    , publicKey(publicKey)
{

}

template<class POINT_TYPE, class NUMBER_TYPE>
KeyPair KeyPair::generate() {
  auto sk = PrivateKey<NUMBER_TYPE>::generate();
  return std::move(KeyPair(std::move(sk)));
}

template<class POINT_TYPE, class NUMBER_TYPE>
const PublicKey<POINT_TYPE, NUMBER_TYPE>& KeyPair::get_public_key() const {
  return public_key_;
}

template<class POINT_TYPE, class NUMBER_TYPE>
const PrivateKey<NUMBER_TYPE>& KeyPair::get_private_key() const {
  return private_key_;
}

} // namespace SkyCryptor
