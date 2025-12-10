import * as bcrypt from 'bcryptjs';

export const generateSalt = async (): Promise<string> => {
  return bcrypt.genSalt(10);
};

export async function comparePassword(
  newPassword: string,
  oldPassword: string,
) {
  const result = await bcrypt.compare(newPassword, oldPassword);
  return result;
}

export const hashedOtpOrPassword = async (data: string) => {
  const salt = await generateSalt();
  return bcrypt.hash(data, salt);
};

export function generateOTP() {
  // Generate a random number between 1000 and 9999
  const otp = Math.floor(Math.random() * 900000) + 100000;
  return otp;
}
