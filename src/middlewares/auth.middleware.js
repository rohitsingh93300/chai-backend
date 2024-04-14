import { ApiError } from "../utils/apiError.js"
import jwt from "jsonwebtoken"
import { asyncHandler } from "../utils/asyncHandler.js"
import { User } from "../models/user.model.js"

export const verifyJwt = asyncHandler(async(req, _, next)=>{
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "" )

        if(!token){
            throw new ApiError(401, "Unauthorized request")
        }

       const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)

       const user = await User.findById(decodedToken?._id).select("-password -refreshToken")

       if(!user){
        // todo : disscuss about frontend 
        throw new ApiError(401, "Invalid access token")
       }

       req.user = user;
       next()
    } catch (error) {
        return new ApiError(401, error?.message || "Invalid Access Token")
    }
})