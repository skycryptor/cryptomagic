namespace SkyCryptor {

template<class POINT_TYPE, class NUMBER_TYPE>
PrivateKey<POINT_TYPE, NUMBER_TYPE>::PrivateKey(const NUMBER_TYPE& private_key) 
  : private_key_(private_key)
{
}

template<class POINT_TYPE, class NUMBER_TYPE>
PrivateKey<POINT_TYPE, NUMBER_TYPE>::PrivateKey()
  : private_key_(NUMBER_TYPE::generate_random())
{
}

template<class POINT_TYPE, class NUMBER_TYPE>
PublicKey<POINT_TYPE, NUMBER_TYPE> PrivateKey<POINT_TYPE, NUMBER_TYPE>::get_public_key() const {
  // Making public key out of given/initialized bigNumber. 
  auto g = POINT_TYPE::get_generator();
  auto point = private_key_ * g;
  return PublicKey<POINT_TYPE, NUMBER_TYPE>(point);
}

template<class POINT_TYPE, class NUMBER_TYPE>
PrivateKey<POINT_TYPE, NUMBER_TYPE> PrivateKey<POINT_TYPE, NUMBER_TYPE>::generate() {
  auto private_key = NUMBER_TYPE::generate_random();
  return PrivateKey<POINT_TYPE, NUMBER_TYPE>(private_key);
}

template<class POINT_TYPE, class NUMBER_TYPE>
const NUMBER_TYPE& PrivateKey<POINT_TYPE, NUMBER_TYPE>::get_key_value() const {
  return private_key_;
}

} // namespace SkyCryptor
