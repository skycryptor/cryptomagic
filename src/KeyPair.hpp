namespace SkyCryptor {

template<class POINT_TYPE, class NUMBER_TYPE>
KeyPair<POINT_TYPE, NUMBER_TYPE>::KeyPair(const PrivateKey<POINT_TYPE, NUMBER_TYPE>& private_key)
    : private_key_(private_key)
    , public_key_(private_key.get_public_key())
{

}

template<class POINT_TYPE, class NUMBER_TYPE>
KeyPair<POINT_TYPE, NUMBER_TYPE>::KeyPair(const PrivateKey<POINT_TYPE, NUMBER_TYPE>& private_key, 
                 const PublicKey<POINT_TYPE, NUMBER_TYPE>& public_key) 
    : private_key_(private_key)
    , public_key_(public_key)
{

}

template<class POINT_TYPE, class NUMBER_TYPE>
KeyPair<POINT_TYPE, NUMBER_TYPE> KeyPair<POINT_TYPE, NUMBER_TYPE>::generate() {
  return KeyPair<POINT_TYPE, NUMBER_TYPE>(PrivateKey<POINT_TYPE, NUMBER_TYPE>::generate());
}

template<class POINT_TYPE, class NUMBER_TYPE>
const PublicKey<POINT_TYPE, NUMBER_TYPE>& KeyPair<POINT_TYPE, NUMBER_TYPE>::get_public_key() const {
  return public_key_;
}

template<class POINT_TYPE, class NUMBER_TYPE>
const PrivateKey<POINT_TYPE, NUMBER_TYPE>& KeyPair<POINT_TYPE, NUMBER_TYPE>::get_private_key() const {
  return private_key_;
}

} // namespace SkyCryptor
