const jwt = require('jsonwebtoken');
const CryptoJS = require("crypto-js");
const axios = require("axios");
const moment = require('moment');

const singInJwt = async (nonce, encryptedSub, TokenInfo) => {
  try {
      const expires = moment().add(TokenInfo.JWT_EXPIRY, "seconds");
      const payload = {
          nonce,
          sub: encryptedSub ,
          iat: (new Date()).getTime(),
          exp: expires.unix(),
          type: TokenInfo.JWT_TOKEN_TYPE,
      };

      return jwt.sign(payload, TokenInfo.JWT_SECRET);
  } catch {
      console.log("error in sign jwt token internal ", error);
      throw error;
  }
};

const generateToken = async (nonce, user, tllmsVerification, accessTokenInfo) => {
  try{
    const { userId, token, key, secretKey, identifier, appId, tllmsBaseUrl } = tllmsVerification;
    const tllmsRes = await verifyUserAtTllms(tllmsBaseUrl, userId, token, appId, key, secretKey, identifier);

    const newUserData = JSON.stringify({ user: user, tllmsRes: tllmsRes })
    const encryptedSub = CryptoJS.AES.encrypt(newUserData, accessTokenInfo.JWT_SALT).toString();

    const accessToken = await singInJwt(nonce, encryptedSub, accessTokenInfo);

    return { token: accessToken, userDetails: tllmsRes, nonce };
  } catch (error) {
    console.log("error in sign jwt token ", error);
    throw (error);
  }
  
};

const verifyToken = (authToken, secret, salt) => {
  try {
    let decreptedToken =  jwt.verify(authToken, secret);
    const bytes = CryptoJS.AES.decrypt(decreptedToken.sub, salt);
    const decryptedSub = bytes.toString(CryptoJS.enc.Utf8);
    decreptedToken.sub = JSON.parse(decryptedSub);
    return decreptedToken;
  } catch (error) {
    throw ({
      "message": "jwt expired",
      "status": "expired",
      "expiredAt": error.expiredAt
    })
  }
};

const verifyUserAtTllms = async (tllmsBaseUrl, userId, token,  appId, TllmsKey, tllmsSecret, tllmsIdentifier) => {
  try{
    const options = {
      method: "get",
      url: `${tllmsBaseUrl}/internal_api/v1/profiles/${userId}?token=${token}&key=${TllmsKey}&secret=${tllmsSecret}&identifier=${tllmsIdentifier}`,
      headers: {
          "Content-Type": "application/json",
          "Accept": "*/*",
          "Accept-Encoding": "*",
          "X-TNL-APPID": parseInt(appId),
          },
      };
      const response = await axios(options);
      return response.data;
  }catch(error){
    console.log("error in verify user at tlllms ");
    throw error
  }
};

module.exports = {generateToken, verifyToken,  singInJwt};