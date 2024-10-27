import { Router } from "express";
import {
  loginUser,
  logoutUser,
  registerUser,
  refreshAccessToken,
  changeCurrentPassword,
  getCurrentUser,
  updateAccountDetails,
  updateUserAvatar,
  updateUserCoverImage,
  getUserChannelProfile,
  getWatchHistory,
} from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middleware.js";
import { verifytJWT } from "../middlewares/auth.middleware.js";
const router = Router();

router.route("/register").post(
  upload.fields([
    {
      name: "avatar",
      maxCount: 1,
    },
    {
      name: "coverImage",
      maxCount: 1,
    },
  ]),
  registerUser
);
// router.route("/register").post(,login); // only for understanding

router.route("/login").post(loginUser);

//secured routes
router.route("/logout").post(verifytJWT, logoutUser);
router.route("/refresh-token").post(refreshAccessToken);
router.route("/change-password").post(verifytJWT, changeCurrentPassword);
router.route("/current-user").get(verifytJWT, getCurrentUser);
router.route("/update-account").patch(verifytJWT, updateAccountDetails);
router
  .route("/avatar")
  .patch(verifytJWT, upload.single("avatar"), updateUserAvatar);
router
  .route("/cover-image")
  .patch(verifytJWT, upload.single("coverImage"), updateUserCoverImage);
router.route("/c/:username").get(verifytJWT, getUserChannelProfile);
router.route("/history").get(verifytJWT, getWatchHistory);

export default router;
