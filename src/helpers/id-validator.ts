import mongoose from 'mongoose';

export const isValidMongooseId = async (id: string) => {
  const isValidId = mongoose.Types.ObjectId.isValid(id);
  return isValidId;
};
