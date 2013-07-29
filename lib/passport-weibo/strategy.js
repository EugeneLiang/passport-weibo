/**
 * Module dependencies.
 */
var util = require('util'),
OAuth2Strategy = require('passport-oauth').OAuth2Strategy,
InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The weibo authentication strategy authenticates requests by delegating to
 * weibo using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your weibo application's app key
 *   - `clientSecret`  your weibo application's app secret
 *   - `callbackURL`   URL to which weibo will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new WeiboStrategy({
 *         clientID: 'app key',
 *         clientSecret: 'app secret'
 *         callbackURL: 'https://www.example.net/auth/weibo/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://api.weibo.com/oauth2/authorize';
  options.tokenURL = options.tokenURL || 'https://api.weibo.com/oauth2/access_token';
  options.scopeSeparator = options.scopeSeparator || ',';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'weibo';
}


/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from weibo.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `weibo`
 *   - `id`               user's weibo ID
 *   - `username`         name of user's weibo account
 *   - `displayName`      screen name of user's weibo account
 *   - `name`             an empty object
 *   - `gender`           user gender
 *   - `profileUrl`       url to the users weibo profile
 *   - `emails`           list of user's emails
 *   - `photos`           list of user's pictures
 *
 * See Passport.js user profile schema: http://passportjs.org/guide/profile/
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  var oauth2 = this._oauth2;
  oauth2.get('https://api.weibo.com/2/account/get_uid.json', accessToken, function (err, uid, res) {
    if (err) {
      return done(new InternalOAuthError('failed to fetch user profile', err));
    }

    uid = JSON.parse(uid);
    oauth2.get('https://api.weibo.com/2/users/show.json?uid=' + uid.uid, accessToken, function (err, body, res) {
      var json = JSON.parse(body);

      oauth2.get('https://api.weibo.com/2/account/profile/email.json', accessToken, function(err, email, res) {
        try {
          var profile = {
            provider: 'weibo',
            id: json.id,
            username: json.name,
            displayName: json.screen_name,
            // NOTE: Weibo profile doesn't have family_name, given_name etc.
            name: {},
            gender: json.gender,
            profileUrl: 'http://weibo.com/' + json.profile_url,
            emails: [{
              value: JSON.parse(email).email
            }],
            photos: [{
              value: json.profile_image_url
            }],

            _raw: body,
            _json: json
          };

          done(null, profile);
        } catch(e) {
          done(e);
        }
      });
    });
  });
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
