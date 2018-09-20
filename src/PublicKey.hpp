namespace SkyCryptor {

template<class POINT_TYPE, class NUMBER_TYPE>
PublicKey::PublicKey(const Point &ec_point, Context *ctx)
    : point_(ctx)
    , context_(ctx)
{
}

template<class POINT_TYPE, class NUMBER_TYPE>
PublicKey::PublicKey(const Context& ctx) 
    : point_(*ctx) // Martun: this will generate a random point???
    , context_(ctx)
{
}

template<class POINT_TYPE, class NUMBER_TYPE>
bool PublicKey::operator==(const PublicKey &publicKey) const {
  return point == publicKey;
}

template<class POINT_TYPE, class NUMBER_TYPE>
const Point& PublicKey::get_point() const {
  return point;
}

template<class POINT_TYPE, class NUMBER_TYPE>
PublicKey::PublicKey(const PublicKey &pk) {
  context = pk.context;
  point = pk.point;
}

} // namespace SkyCryptor
