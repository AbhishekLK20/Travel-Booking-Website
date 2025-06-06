const { redisClient } = require("../config/redis");
const { SECRET_KEY } = require("../constants");
const { User } = require("../models/user.model");
const { ApiResponse } = require("../utils/ApiResponse");
const { sendEmail } = require("../utils/EmailSender");
const {
  generateOTP,
  getStoredOTP,
  removeStoredOTP,
} = require("../utils/OtpGenerator");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// Register a new user
const register = async (req, res) => {
  try {
    const { fullname, email, password, isVerified } = req.body;

    if (!fullname || !email || !password) {
      return ApiResponse.error(res, [], 400, "All fields are required");
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return ApiResponse.error(res, [], 409, "Email already in use");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      fullname,
      email,
      password: hashedPassword,
      isVerified,
    });

    await user.save();

    ApiResponse.success(
      res,
      { userId: user._id },
      201,
      "User registered successfully"
    );
  } catch (err) {
    console.error("Error in register:", err);
    ApiResponse.error(res, [err.message], 500, "Failed to register user");
  }
};

// User login
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return ApiResponse.error(res, [], 400, "Email and password are required");
    }

    const user = await User.findOne({ email });
    if (!user) {
      return ApiResponse.error(
        res,
        ["User not found"],
        404,
        "Invalid credentials"
      );
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return ApiResponse.error(res, [], 401, "Invalid credentials");
    }

    const token = jwt.sign({ userId: user._id, role: user.role }, SECRET_KEY, {
      expiresIn: "1h",
    });

    ApiResponse.success(res, { token }, 200, "Login successful");
  } catch (err) {
    console.error("Error in login:", err);
    ApiResponse.error(res, [err.message], 500, "Failed to log in");
  }
};

// Resend OTP
const resendOTP = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return ApiResponse.error(res, [], 400, "Email is required");
    }

    const otp = await generateOTP(email);
    const emailStatus = await sendEmail(
      email,
      "Voyawander email verification code",
      `Your OTP is ${otp}`
    );

    if (emailStatus) {
      ApiResponse.success(res, {}, 200, "OTP sent successfully");
    } else {
      throw Error("Failed to send email");
    }
  } catch (error) {
    console.error(error);
    return ApiResponse.error(res, [], 500, "Something went wrong!");
  }
};

// Check OTP
const checkOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return ApiResponse.error(
        res,
        [],
        400,
        "Email and OTP are required!"
      );
    }

    const storedOTP = await getStoredOTP(email);
    if (!storedOTP) {
      return ApiResponse.error(res, ["OTP expired!"], 404, "OTP expired!");
    }

    if (storedOTP === otp) {
      removeStoredOTP(email);
      return ApiResponse.success(
        res,
        { verified: true },
        200,
        "Email verified successfully!"
      );
    }

    return ApiResponse.error(
      res,
      ["Expired or Invalid OTP"],
      400,
      "Expired or Invalid OTP"
    );
  } catch (error) {
    console.error("Error while Checking OTP");
    return ApiResponse.error(res, [error.message], 500, "Server error");
  }
};

// Update Password
const updatePassword = async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
      return ApiResponse.error(
        res,
        [],
        400,
        "Old and new passwords are required"
      );
    }

    const userId = req.user.userId;
    const user = await User.findById(userId);

    if (!user) {
      return ApiResponse.error(res, [], 404, "User not found");
    }

    const isOldPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isOldPasswordValid) {
      return ApiResponse.error(res, [], 401, "Old password is incorrect");
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedNewPassword;

    await user.save();

    ApiResponse.success(res, {}, 200, "Password updated successfully");
  } catch (err) {
    console.error("Error in updatePassword:", err);
    ApiResponse.error(res, [err.message], 500, "Failed to update password");
  }
};

// Forget Password (Refactored for low complexity)
const forgetPassword = async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!email) {
      return ApiResponse.error(res, ["Validation Error"], 401, "The email field is required.");
    }

    const existingUser = await User.findOne({ email });
    if (!existingUser) {
      return ApiResponse.error(res, ["Resource Not Found"], 404, "The provided email is not registered.");
    }

    const handleResendOTP = async () => {
      return await resendOTP(req, res);
    };

    const handleOTPVerification = async () => {
      const storedOTP = await getStoredOTP(email);
      if (!storedOTP) {
        return ApiResponse.error(res, ["OTP expired!"], 404, "OTP expired!");
      }
      if (otp !== storedOTP) {
        return ApiResponse.error(res, ["Invalid or expired OTP"], 400, "Invalid or expired OTP");
      }

      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      const user = await User.findOneAndUpdate(
        { email },
        { $set: { password: hashedNewPassword } },
        { new: true }
      );

      if (!user) {
        return ApiResponse.error(res, ["User not found!"], 404, "User not found!");
      }

      removeStoredOTP(email);
      return ApiResponse.success(res, {}, 200, "Password updated successfully");
    };

    if (!otp && !newPassword) {
      return await handleResendOTP();
    }

    if (otp && newPassword) {
      return await handleOTPVerification();
    }

    return ApiResponse.error(res, [], 409, "Required all details!");
  } catch (error) {
    return ApiResponse.error(res, [error.message], 500, "Unexpected error");
  }
};

// Verify Email
const verifyEmail = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return ApiResponse.error(res, [], 400, "Email is required");
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return ApiResponse.error(res, [], 409, "Email already in use");
    }

    const otp = await generateOTP(email);

    await sendEmail(
      email,
      "Voyawander email verification code",
      `Your OTP is ${otp}`
    );

    return ApiResponse.success(res, {}, 200, "OTP sent for verification successfully");
  } catch (err) {
    console.error("Error in OTP sending for Email verification:", err);
    return ApiResponse.error(res, [err.message], 500, "Failed to send verification OTP email");
  }
};

module.exports = {
  register,
  login,
  resendOTP,
  checkOTP,
  updatePassword,
  forgetPassword,
  verifyEmail,
};
