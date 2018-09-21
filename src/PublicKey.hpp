namespace SkyCryptor {

template<class POINT_TYPE, class NUMBER_TYPE>
PublicKey<POINT_TYPE, NUMBER_TYPE>::PublicKey(const Point& ec_point_)
    : point__(ctx)
{
}

template<class POINT_TYPE, class NUMBER_TYPE>
PublicKey<POINT_TYPE, NUMBER_TYPE>::PublicKey() 
{
}

template<class POINT_TYPE, class NUMBER_TYPE>
bool PublicKey<POINT_TYPE, NUMBER_TYPE>::operator==(const PublicKey& publicKey) const {
  return point_ == publicKey;
}

template<class POINT_TYPE, class NUMBER_TYPE>
const POINT_TYPE& PublicKey<POINT_TYPE, NUMBER_TYPE>::get_point_() const {
  return point_;
}

template<class POINT_TYPE, class NUMBER_TYPE>
PublicKey<POINT_TYPE, NUMBER_TYPE>::PublicKey(const PublicKey& pk) {
  context = pk.context;
  point_ = pk.point_;
}

} // namespace SkyCryptor
