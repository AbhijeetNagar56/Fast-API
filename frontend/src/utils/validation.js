export const AGE_MIN = 1;
export const AGE_MAX = 120;

export const parseAge = (value) => {
  if (value === null || value === undefined || value === "") return null;
  const age = Number(value);
  if (!Number.isInteger(age)) return null;
  if (age < AGE_MIN || age > AGE_MAX) return null;
  return age;
};

export const isValidGender = (gender) =>
  ["Male", "Female", "Other"].includes(gender);

export const isValidPhoneNumber = (value) =>
  typeof value === "string" && /^\d{10}$/.test(value.trim());
