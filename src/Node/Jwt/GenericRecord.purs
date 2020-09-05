module Node.Jwt.GenericRecord where

import Foreign.Generic.Class (class DecodeRecord, class EncodeRecord)
import Prim.RowList (class RowToList)

class (EncodeRecord r l, RowToList r l) <= Encodable r l

instance encodableInstance ::
  ( EncodeRecord r l, RowToList r l
  ) =>
  Encodable r l

class (DecodeRecord r l, RowToList r l) <= Decodable r l

instance decodableInstance ::
  ( DecodeRecord r l, RowToList r l
  ) =>
  Decodable r l
