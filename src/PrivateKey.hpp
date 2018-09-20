namespace SkyCryptor {

template<class NUMBER_TYPE>
PrivateKey::PrivateKey(const NUMBER_TYPE& private_key) 
  : private_key_(private_key)
{
}

template<class NUMBER_TYPE>
PrivateKey::PrivateKey()
  : private_key_(NUMBER_TYPE::generate_random())
{
}

template<class NUMBER_TYPE>
PublicKey PrivateKey::get_public_key() const {
  // Making public key out of given/initialized bigNumber and context
  auto g = Point::get_generator(context.get());
  auto point = bigNumber * g;
  return std::move(PublicKey(point));
}

template<class NUMBER_TYPE>
PrivateKey PrivateKey::generate() {
  auto private_key = NUMBER_TYPE::generate_random();
  return PrivateKey(private_key);
}

template<class NUMBER_TYPE>
const NUMBER_TYPE& PrivateKey::get_key_value() const {
  return private_key_;
}

} // namespace SkyCryptor
