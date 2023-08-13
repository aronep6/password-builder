const isAllowedValue = (value: string, allowedValues: string[]): boolean => {
  if (typeof value !== "string") {
    return false;
  }

  return allowedValues.includes(value);
};

export default isAllowedValue;
