namespace SkyCryptor {

template<class POINT_TYPE, class NUMBER_TYPE>
PublicKey<POINT_TYPE, NUMBER_TYPE>::PublicKey(const POINT_TYPE& point)
    : point_(point)
{
}

template<class POINT_TYPE, class NUMBER_TYPE>
PublicKey<POINT_TYPE, NUMBER_TYPE>::PublicKey() 
{
}

template<class POINT_TYPE, class NUMBER_TYPE>
bool PublicKey<POINT_TYPE, NUMBER_TYPE>::operator==(
    const PublicKey<POINT_TYPE, NUMBER_TYPE>& publicKey) const {
  return point_ == publicKey;
}

template<class POINT_TYPE, class NUMBER_TYPE>
const POINT_TYPE& PublicKey<POINT_TYPE, NUMBER_TYPE>::get_point() const {
  return point_;
}

} // namespace SkyCryptor
