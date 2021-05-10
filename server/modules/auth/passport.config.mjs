import log from "@ajar/marker";
import passport from "passport";
import passportFacebook from "passport-facebook";
import passportGithub from "passport-github";

const {
  PORT,
  HOST,
  GITHUB_KEY,
  GITHUB_SECRET,
  FACEBOOK_KEY,
  FACEBOOK_SECRET,
} = process.env;

const GITHUB_CONFIG = {
  clientID: GITHUB_KEY,
  clientSecret: GITHUB_SECRET,
  callbackURL: `http://${HOST}:${PORT}/api/auth/github/callback`,
  // passReqToCallback: true
};

const { Strategy: GithubStrategy } = passportGithub;

export default () => {
  // Allowing passport to serialize and deserialize users into sessions
  passport.serializeUser((user, cb) => cb(null, user));
  passport.deserializeUser((user, cb) => cb(null, user));

  // -----------------------------
  //          GITHUB
  // -----------------------------
  passport.use(
    new GithubStrategy(
      GITHUB_CONFIG,
      async (accessToken, refreshToken, profile, cb) => {
        try {
          log.d("accessToken:", accessToken);
          log.d("refreshToken:", refreshToken);
          log.v("displayName:", profile.displayName);

          //create or update user
          // let user = await user_model.findOneAndUpdate(
          //   {'github.id':profile.id},
          //   {
          //     'github.id':profile.id,
          //     'github.token':accessToken,
          //     'github.displayName':profile.displayName,
          //     'github.username':profile.username,
          //     'github.emails':profile.emails,
          //     'github.photos':profile.photos
          //   },
          //   { new:true,upsert:true});

          // return cb(null, user); //logs in the user
          return cb(null, profile); //logs in the user
        } catch (err) {
          return cb(err);
        }
      }
    )
  );
};
