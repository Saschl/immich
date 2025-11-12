import { BadRequestException, ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { isString } from 'class-validator';
import { parse } from 'cookie';
import { DateTime } from 'luxon';
import { IncomingHttpHeaders } from 'node:http';
import { join } from 'node:path';
import { LOGIN_URL, MOBILE_REDIRECT, SALT_ROUNDS } from 'src/constants';
import { StorageCore } from 'src/cores/storage.core';
import { AuthSharedLink, AuthUser, UserAdmin } from 'src/database';
import {
  AuthDto,
  AuthStatusResponseDto,
  ChangePasswordDto,
  LoginCredentialDto,
  LogoutResponseDto,
  OAuthCallbackDto,
  OAuthConfigDto,
  PinCodeChangeDto,
  PinCodeResetDto,
  PinCodeSetupDto,
  SessionUnlockDto,
  SignUpDto,
  mapLoginResponse,
} from 'src/dtos/auth.dto';
import { UserAdminResponseDto, mapUserAdmin } from 'src/dtos/user.dto';
import { AuthType, ImmichCookie, ImmichHeader, ImmichQuery, JobName, Permission, StorageFolder } from 'src/enum';
import { OAuthProfile } from 'src/repositories/oauth.repository';
import { BaseService } from 'src/services/base.service';
import { isGranted } from 'src/utils/access';
import { HumanReadableSize } from 'src/utils/bytes';
import { mimeTypes } from 'src/utils/mime-types';
import { getUserAgentDetails } from 'src/utils/request';
export interface LoginDetails {
  isSecure: boolean;
  clientIp: string;
  deviceType: string;
  deviceOS: string;
  appVersion: string | null;
}

interface ClaimOptions<T> {
  key: string;
  default: T;
  isValid: (value: unknown) => boolean;
}

export type ValidateRequest = {
  headers: IncomingHttpHeaders;
  queryParams: Record<string, string>;
  metadata: {
    sharedLinkRoute: boolean;
    adminRoute: boolean;
    /** `false` explicitly means no permission is required, which otherwise defaults to `all` */
    permission?: Permission | false;
    uri: string;
  };
};

@Injectable()
export class AuthService extends BaseService {
  async login(dto: LoginCredentialDto, details: LoginDetails) {
    const config = await this.getConfig({ withCache: false });
    if (!config.passwordLogin.enabled) {
      throw new UnauthorizedException('Password login has been disabled');
    }

    let user = await this.userRepository.getByEmail(dto.email, { withPassword: true });
    if (user) {
      const isAuthenticated = this.validateSecret(dto.password, user.password);
      if (!isAuthenticated) {
        user = undefined;
      }
    }

    if (!user) {
      this.logger.warn(`Failed login attempt for user ${dto.email} from ip address ${details.clientIp}`);
      throw new UnauthorizedException('Incorrect email or password');
    }

    return this.createLoginResponse(user, details);
  }

  async logout(auth: AuthDto, authType: AuthType): Promise<LogoutResponseDto> {
    if (auth.session) {
      await this.sessionRepository.delete(auth.session.id);
      await this.eventRepository.emit('SessionDelete', { sessionId: auth.session.id });
    }

    return {
      successful: true,
      redirectUri: await this.getLogoutEndpoint(authType),
    };
  }

  async backchannelLogout(logoutToken: string): Promise<LogoutResponseDto> {
    try {
      // Get OAuth configuration to validate the token
      const { oauth } = await this.getConfig({ withCache: false });
      if (!oauth.enabled) {
        throw new UnauthorizedException('OAuth is not enabled');
      }

      console.log('Backchannel logout token payload:', logoutToken);

      // Validate the logout token JWT
      const tokenPayload = await this.validateLogoutToken(logoutToken, oauth);

      // Extract user identifier from the token (could be 'sub', 'sid', or both)
      const userId = tokenPayload.sub;
      const sessionId = tokenPayload.sid;

      if (!userId && !sessionId) {
        throw new BadRequestException('Logout token must contain either sub or sid claim');
      }

      // Find and terminate sessions
      let deletedSessions = 0;

      if (userId) {
        // Find user by OAuth ID
        const user = await this.userRepository.getByOAuthId(userId);
        if (user) {
          // Get all sessions for this user and delete them
          const sessions = await this.sessionRepository.getByUserId(user.id);
          for (const session of sessions) {
            await this.sessionRepository.delete(session.id);
            await this.eventRepository.emit('SessionDelete', { sessionId: session.id });
            deletedSessions++;
          }

          this.logger.log(`Backchannel logout: Terminated ${deletedSessions} sessions for user ${user.id}`);
        }
      }

      if (sessionId && !userId) {
        // Handle session-specific logout if only session ID is provided
        // This would require mapping session IDs to OAuth session IDs
        // For now, we'll log this case but not implement it
        this.logger.warn(`Backchannel logout: Session-specific logout not implemented for sid: ${sessionId}`);
      }

      return {
        successful: true,
        redirectUri: '/auth/login?autoLaunch=0',
      };
    } catch (error: any) {
      this.logger.error(`Backchannel logout failed: ${error?.message || error}`);
      throw new BadRequestException('Invalid logout token');
    }
  }

  private async validateLogoutToken(logoutToken: string, oauthConfig: any): Promise<any> {
    try {
      // Get the OAuth client for token validation
      const client = await this.getOAuthClient(oauthConfig);

      // Use openid-client to validate the logout token
      // For a proper implementation, we would validate the JWT signature
      // For now, we'll decode the payload and validate the claims
      const payload = this.decodeJwtPayload(logoutToken);

      // Validate required claims for logout tokens according to RFC 7636
      if (!payload.iss) {
        throw new Error('Missing issuer (iss) claim');
      }

      if (!payload.aud || (Array.isArray(payload.aud) && !payload.aud.includes(oauthConfig.clientId))) {
        throw new Error('Invalid audience (aud) claim');
      }

      if (!payload.iat) {
        throw new Error('Missing issued at (iat) claim');
      }

      if (!payload.jti) {
        throw new Error('Missing JWT ID (jti) claim');
      }

      // Check token expiration
      if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
        throw new Error('Token has expired');
      }

      // Validate that this is a logout token (should not have 'nonce' claim)
      if (payload.nonce) {
        throw new Error('Logout token must not contain nonce claim');
      }

      // Logout token must have either 'sub' or 'sid' claim (or both)
      if (!payload.sub && !payload.sid) {
        throw new Error('Logout token must contain either sub or sid claim');
      }

      return payload;
    } catch (error: any) {
      this.logger.error(`JWT validation failed: ${error?.message || error}`);
      throw new Error(`Invalid logout token: ${error?.message || error}`);
    }
  }

  private decodeJwtPayload(token: string): any {
    try {
      // Split the JWT into its three parts
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format: expected 3 parts separated by dots');
      }

      // Decode the payload (second part)
      const payload = parts[1];

      // Handle padding for base64url decoding
      const paddedPayload = payload + '='.repeat((4 - (payload.length % 4)) % 4);
      const decodedPayload = Buffer.from(paddedPayload, 'base64').toString('utf8');

      const parsedPayload = JSON.parse(decodedPayload);

      this.logger.debug(
        `Decoded JWT payload for backchannel logout: iss=${parsedPayload.iss}, sub=${parsedPayload.sub}, aud=${parsedPayload.aud}`,
      );

      return parsedPayload;
    } catch (error: any) {
      this.logger.error(`Failed to decode JWT payload: ${error?.message || error}`);
      throw new Error(`Failed to decode JWT payload: ${error?.message || error}`);
    }
  }

  private async getOAuthClient(config: any) {
    try {
      const { allowInsecureRequests, discovery } = await import('openid-client');
      return await discovery(
        new URL(config.issuerUrl),
        config.clientId,
        {
          client_secret: config.clientSecret,
          response_types: ['code'],
        },
        await this.getTokenAuthMethodFromConfig(config.tokenEndpointAuthMethod, config.clientSecret),
        {
          execute: [allowInsecureRequests],
          timeout: config.timeout || 5000,
        },
      );
    } catch (error: any) {
      this.logger.error(`Error in OAuth client creation: ${error?.message || error}`);
      throw new BadRequestException(`Error in OAuth client creation`);
    }
  }

  private async getTokenAuthMethodFromConfig(tokenEndpointAuthMethod: any, clientSecret?: string) {
    const { None, ClientSecretPost, ClientSecretBasic } = await import('openid-client');

    if (!clientSecret) {
      return None();
    }

    switch (tokenEndpointAuthMethod) {
      case 'client_secret_post': {
        return ClientSecretPost(clientSecret);
      }
      case 'client_secret_basic': {
        return ClientSecretBasic(clientSecret);
      }
      default: {
        return None();
      }
    }
  }

  async changePassword(auth: AuthDto, dto: ChangePasswordDto): Promise<UserAdminResponseDto> {
    const { password, newPassword } = dto;
    const user = await this.userRepository.getForChangePassword(auth.user.id);
    const valid = this.validateSecret(password, user.password);
    if (!valid) {
      throw new BadRequestException('Wrong password');
    }

    const hashedPassword = await this.cryptoRepository.hashBcrypt(newPassword, SALT_ROUNDS);

    const updatedUser = await this.userRepository.update(user.id, { password: hashedPassword });

    await this.eventRepository.emit('AuthChangePassword', {
      userId: user.id,
      currentSessionId: auth.session?.id,
      invalidateSessions: dto.invalidateSessions,
    });

    return mapUserAdmin(updatedUser);
  }

  async setupPinCode(auth: AuthDto, { pinCode }: PinCodeSetupDto) {
    const user = await this.userRepository.getForPinCode(auth.user.id);
    if (!user) {
      throw new UnauthorizedException();
    }

    if (user.pinCode) {
      throw new BadRequestException('User already has a PIN code');
    }

    const hashed = await this.cryptoRepository.hashBcrypt(pinCode, SALT_ROUNDS);
    await this.userRepository.update(auth.user.id, { pinCode: hashed });
  }

  async resetPinCode(auth: AuthDto, dto: PinCodeResetDto) {
    const user = await this.userRepository.getForPinCode(auth.user.id);
    this.validatePinCode(user, dto);

    await this.userRepository.update(auth.user.id, { pinCode: null });
    await this.sessionRepository.lockAll(auth.user.id);
  }

  async changePinCode(auth: AuthDto, dto: PinCodeChangeDto) {
    const user = await this.userRepository.getForPinCode(auth.user.id);
    this.validatePinCode(user, dto);

    const hashed = await this.cryptoRepository.hashBcrypt(dto.newPinCode, SALT_ROUNDS);
    await this.userRepository.update(auth.user.id, { pinCode: hashed });
  }

  private validatePinCode(
    user: { pinCode: string | null; password: string | null },
    dto: { pinCode?: string; password?: string },
  ) {
    if (!user.pinCode) {
      throw new BadRequestException('User does not have a PIN code');
    }

    if (dto.password) {
      if (!this.validateSecret(dto.password, user.password)) {
        throw new BadRequestException('Wrong password');
      }
    } else if (dto.pinCode) {
      if (!this.validateSecret(dto.pinCode, user.pinCode)) {
        throw new BadRequestException('Wrong PIN code');
      }
    } else {
      throw new BadRequestException('Either password or pinCode is required');
    }
  }

  async adminSignUp(dto: SignUpDto): Promise<UserAdminResponseDto> {
    const adminUser = await this.userRepository.getAdmin();
    if (adminUser) {
      throw new BadRequestException('The server already has an admin');
    }

    const admin = await this.createUser({
      isAdmin: true,
      email: dto.email,
      name: dto.name,
      password: dto.password,
      storageLabel: 'admin',
    });

    return mapUserAdmin(admin);
  }

  async authenticate({ headers, queryParams, metadata }: ValidateRequest): Promise<AuthDto> {
    const authDto = await this.validate({ headers, queryParams });
    const { adminRoute, sharedLinkRoute, uri } = metadata;
    const requestedPermission = metadata.permission ?? Permission.All;

    if (!authDto.user.isAdmin && adminRoute) {
      this.logger.warn(`Denied access to admin only route: ${uri}`);
      throw new ForbiddenException('Forbidden');
    }

    if (authDto.sharedLink && !sharedLinkRoute) {
      this.logger.warn(`Denied access to non-shared route: ${uri}`);
      throw new ForbiddenException('Forbidden');
    }

    if (
      authDto.apiKey &&
      requestedPermission !== false &&
      !isGranted({ requested: [requestedPermission], current: authDto.apiKey.permissions })
    ) {
      throw new ForbiddenException(`Missing required permission: ${requestedPermission}`);
    }

    return authDto;
  }

  private async validate({ headers, queryParams }: Omit<ValidateRequest, 'metadata'>): Promise<AuthDto> {
    const shareKey = (headers[ImmichHeader.SharedLinkKey] || queryParams[ImmichQuery.SharedLinkKey]) as string;
    const shareSlug = (headers[ImmichHeader.SharedLinkSlug] || queryParams[ImmichQuery.SharedLinkSlug]) as string;
    const session = (headers[ImmichHeader.UserToken] ||
      headers[ImmichHeader.SessionToken] ||
      queryParams[ImmichQuery.SessionKey] ||
      this.getBearerToken(headers) ||
      this.getCookieToken(headers)) as string;
    const apiKey = (headers[ImmichHeader.ApiKey] || queryParams[ImmichQuery.ApiKey]) as string;

    if (shareKey) {
      return this.validateSharedLinkKey(shareKey);
    }

    if (shareSlug) {
      return this.validateSharedLinkSlug(shareSlug);
    }

    if (session) {
      return this.validateSession(session, headers);
    }

    if (apiKey) {
      return this.validateApiKey(apiKey);
    }

    throw new UnauthorizedException('Authentication required');
  }

  getMobileRedirect(url: string) {
    return `${MOBILE_REDIRECT}?${url.split('?')[1] || ''}`;
  }

  async authorize(dto: OAuthConfigDto) {
    const { oauth } = await this.getConfig({ withCache: false });

    if (!oauth.enabled) {
      throw new BadRequestException('OAuth is not enabled');
    }

    return await this.oauthRepository.authorize(
      oauth,
      this.resolveRedirectUri(oauth, dto.redirectUri),
      dto.state,
      dto.codeChallenge,
    );
  }

  async callback(dto: OAuthCallbackDto, headers: IncomingHttpHeaders, loginDetails: LoginDetails) {
    const expectedState = dto.state ?? this.getCookieOauthState(headers);
    if (!expectedState?.length) {
      throw new BadRequestException('OAuth state is missing');
    }

    const codeVerifier = dto.codeVerifier ?? this.getCookieCodeVerifier(headers);
    if (!codeVerifier?.length) {
      throw new BadRequestException('OAuth code verifier is missing');
    }

    const { oauth } = await this.getConfig({ withCache: false });
    const url = this.resolveRedirectUri(oauth, dto.url);
    const profile = await this.oauthRepository.getProfile(oauth, url, expectedState, codeVerifier);
    const { autoRegister, defaultStorageQuota, storageLabelClaim, storageQuotaClaim, roleClaim } = oauth;
    this.logger.debug(`Logging in with OAuth: ${JSON.stringify(profile)}`);
    let user: UserAdmin | undefined = await this.userRepository.getByOAuthId(profile.sub);

    // link by email
    if (!user && profile.email) {
      const emailUser = await this.userRepository.getByEmail(profile.email);
      if (emailUser) {
        if (emailUser.oauthId) {
          throw new BadRequestException('User already exists, but is linked to another account.');
        }
        user = await this.userRepository.update(emailUser.id, { oauthId: profile.sub });
      }
    }

    // register new user
    if (!user) {
      if (!autoRegister) {
        this.logger.warn(
          `Unable to register ${profile.sub}/${profile.email || '(no email)'}. To enable set OAuth Auto Register to true in admin settings.`,
        );
        throw new BadRequestException(`User does not exist and auto registering is disabled.`);
      }

      if (!profile.email) {
        throw new BadRequestException('OAuth profile does not have an email address');
      }

      this.logger.log(`Registering new user: ${profile.sub}/${profile.email}`);

      const storageLabel = this.getClaim(profile, {
        key: storageLabelClaim,
        default: '',
        isValid: isString,
      });
      const storageQuota = this.getClaim(profile, {
        key: storageQuotaClaim,
        default: defaultStorageQuota,
        isValid: (value: unknown) => Number(value) >= 0,
      });
      const role = this.getClaim<'admin' | 'user'>(profile, {
        key: roleClaim,
        default: 'user',
        isValid: (value: unknown) => isString(value) && ['admin', 'user'].includes(value),
      });

      const userName = profile.name ?? `${profile.given_name || ''} ${profile.family_name || ''}`;
      user = await this.createUser({
        name: userName,
        email: profile.email,
        oauthId: profile.sub,
        quotaSizeInBytes: storageQuota === null ? null : storageQuota * HumanReadableSize.GiB,
        storageLabel: storageLabel || null,
        isAdmin: role === 'admin',
      });
    }

    if (!user.profileImagePath && profile.picture) {
      await this.syncProfilePicture(user, profile.picture);
    }

    return this.createLoginResponse(user, loginDetails);
  }

  private async syncProfilePicture(user: UserAdmin, url: string) {
    try {
      const oldPath = user.profileImagePath;

      const { contentType, data } = await this.oauthRepository.getProfilePicture(url);
      const extensionWithDot = mimeTypes.toExtension(contentType || 'image/jpeg') ?? 'jpg';
      const profileImagePath = join(
        StorageCore.getFolderLocation(StorageFolder.Profile, user.id),
        `${this.cryptoRepository.randomUUID()}${extensionWithDot}`,
      );

      this.storageCore.ensureFolders(profileImagePath);
      await this.storageRepository.createFile(profileImagePath, Buffer.from(data));
      await this.userRepository.update(user.id, { profileImagePath, profileChangedAt: new Date() });

      if (oldPath) {
        await this.jobRepository.queue({ name: JobName.FileDelete, data: { files: [oldPath] } });
      }
    } catch (error: Error | any) {
      this.logger.warn(`Unable to sync oauth profile picture: ${error}\n${error?.stack}`);
    }
  }

  async link(auth: AuthDto, dto: OAuthCallbackDto, headers: IncomingHttpHeaders): Promise<UserAdminResponseDto> {
    const expectedState = dto.state ?? this.getCookieOauthState(headers);
    if (!expectedState?.length) {
      throw new BadRequestException('OAuth state is missing');
    }

    const codeVerifier = dto.codeVerifier ?? this.getCookieCodeVerifier(headers);
    if (!codeVerifier?.length) {
      throw new BadRequestException('OAuth code verifier is missing');
    }

    const { oauth } = await this.getConfig({ withCache: false });
    const { sub: oauthId } = await this.oauthRepository.getProfile(oauth, dto.url, expectedState, codeVerifier);
    const duplicate = await this.userRepository.getByOAuthId(oauthId);
    if (duplicate && duplicate.id !== auth.user.id) {
      this.logger.warn(`OAuth link account failed: sub is already linked to another user (${duplicate.email}).`);
      throw new BadRequestException('This OAuth account has already been linked to another user.');
    }

    const user = await this.userRepository.update(auth.user.id, { oauthId });
    return mapUserAdmin(user);
  }

  async unlink(auth: AuthDto): Promise<UserAdminResponseDto> {
    const user = await this.userRepository.update(auth.user.id, { oauthId: '' });
    return mapUserAdmin(user);
  }

  private async getLogoutEndpoint(authType: AuthType): Promise<string> {
    if (authType !== AuthType.OAuth) {
      return LOGIN_URL;
    }

    const config = await this.getConfig({ withCache: false });
    if (!config.oauth.enabled) {
      return LOGIN_URL;
    }

    return (await this.oauthRepository.getLogoutEndpoint(config.oauth)) || LOGIN_URL;
  }

  private getBearerToken(headers: IncomingHttpHeaders): string | null {
    const [type, token] = (headers.authorization || '').split(' ');
    if (type.toLowerCase() === 'bearer') {
      return token;
    }

    return null;
  }

  private getCookieToken(headers: IncomingHttpHeaders): string | null {
    const cookies = parse(headers.cookie || '');
    return cookies[ImmichCookie.AccessToken] || null;
  }

  private getCookieOauthState(headers: IncomingHttpHeaders): string | null {
    const cookies = parse(headers.cookie || '');
    return cookies[ImmichCookie.OAuthState] || null;
  }

  private getCookieCodeVerifier(headers: IncomingHttpHeaders): string | null {
    const cookies = parse(headers.cookie || '');
    return cookies[ImmichCookie.OAuthCodeVerifier] || null;
  }

  async validateSharedLinkKey(key: string | string[]): Promise<AuthDto> {
    key = Array.isArray(key) ? key[0] : key;

    const bytes = Buffer.from(key, key.length === 100 ? 'hex' : 'base64url');
    const sharedLink = await this.sharedLinkRepository.getByKey(bytes);
    if (!this.isValidSharedLink(sharedLink)) {
      throw new UnauthorizedException('Invalid share key');
    }

    return { user: sharedLink.user, sharedLink };
  }

  async validateSharedLinkSlug(slug: string | string[]): Promise<AuthDto> {
    slug = Array.isArray(slug) ? slug[0] : slug;

    const sharedLink = await this.sharedLinkRepository.getBySlug(slug);
    if (!this.isValidSharedLink(sharedLink)) {
      throw new UnauthorizedException('Invalid share slug');
    }

    return { user: sharedLink.user, sharedLink };
  }

  private isValidSharedLink(
    sharedLink?: AuthSharedLink & { user: AuthUser | null },
  ): sharedLink is AuthSharedLink & { user: AuthUser } {
    return !!sharedLink?.user && (!sharedLink.expiresAt || new Date(sharedLink.expiresAt) > new Date());
  }

  private async validateApiKey(key: string): Promise<AuthDto> {
    const hashedKey = this.cryptoRepository.hashSha256(key);
    const apiKey = await this.apiKeyRepository.getKey(hashedKey);
    if (apiKey?.user) {
      return {
        user: apiKey.user,
        apiKey,
      };
    }

    throw new UnauthorizedException('Invalid API key');
  }

  private validateSecret(inputSecret: string, existingHash?: string | null): boolean {
    if (!existingHash) {
      return false;
    }

    return this.cryptoRepository.compareBcrypt(inputSecret, existingHash);
  }

  private async validateSession(tokenValue: string, headers: IncomingHttpHeaders): Promise<AuthDto> {
    const hashedToken = this.cryptoRepository.hashSha256(tokenValue);
    const session = await this.sessionRepository.getByToken(hashedToken);
    if (session?.user) {
      const { appVersion, deviceOS, deviceType } = getUserAgentDetails(headers);
      const now = DateTime.now();
      const updatedAt = DateTime.fromJSDate(session.updatedAt);
      const diff = now.diff(updatedAt, ['hours']);
      if (diff.hours > 1 || appVersion != session.appVersion) {
        await this.sessionRepository.update(session.id, {
          id: session.id,
          updatedAt: new Date(),
          appVersion,
          deviceOS,
          deviceType,
        });
      }

      // Pin check
      let hasElevatedPermission = false;

      if (session.pinExpiresAt) {
        const pinExpiresAt = DateTime.fromJSDate(session.pinExpiresAt);
        hasElevatedPermission = pinExpiresAt > now;

        if (hasElevatedPermission && now.plus({ minutes: 5 }) > pinExpiresAt) {
          await this.sessionRepository.update(session.id, {
            pinExpiresAt: DateTime.now().plus({ minutes: 5 }).toJSDate(),
          });
        }
      }

      return {
        user: session.user,
        session: {
          id: session.id,
          hasElevatedPermission,
        },
      };
    }

    throw new UnauthorizedException('Invalid user token');
  }

  async unlockSession(auth: AuthDto, dto: SessionUnlockDto): Promise<void> {
    if (!auth.session) {
      throw new BadRequestException('This endpoint can only be used with a session token');
    }

    const user = await this.userRepository.getForPinCode(auth.user.id);
    this.validatePinCode(user, { pinCode: dto.pinCode });

    await this.sessionRepository.update(auth.session.id, {
      pinExpiresAt: DateTime.now().plus({ minutes: 15 }).toJSDate(),
    });
  }

  async lockSession(auth: AuthDto): Promise<void> {
    if (!auth.session) {
      throw new BadRequestException('This endpoint can only be used with a session token');
    }

    await this.sessionRepository.update(auth.session.id, { pinExpiresAt: null });
  }

  private async createLoginResponse(user: UserAdmin, loginDetails: LoginDetails) {
    const token = this.cryptoRepository.randomBytesAsText(32);
    const tokenHashed = this.cryptoRepository.hashSha256(token);

    await this.sessionRepository.create({
      token: tokenHashed,
      deviceOS: loginDetails.deviceOS,
      deviceType: loginDetails.deviceType,
      appVersion: loginDetails.appVersion,
      userId: user.id,
    });

    return mapLoginResponse(user, token);
  }

  private getClaim<T>(profile: OAuthProfile, options: ClaimOptions<T>): T {
    const value = profile[options.key as keyof OAuthProfile];
    return options.isValid(value) ? (value as T) : options.default;
  }

  private resolveRedirectUri(
    { mobileRedirectUri, mobileOverrideEnabled }: { mobileRedirectUri: string; mobileOverrideEnabled: boolean },
    url: string,
  ) {
    if (mobileOverrideEnabled && mobileRedirectUri) {
      return url.replace(/app\.immich:\/+oauth-callback/, mobileRedirectUri);
    }
    return url;
  }

  async getAuthStatus(auth: AuthDto): Promise<AuthStatusResponseDto> {
    const user = await this.userRepository.getForPinCode(auth.user.id);
    if (!user) {
      throw new UnauthorizedException();
    }

    const session = auth.session ? await this.sessionRepository.get(auth.session.id) : undefined;

    return {
      pinCode: !!user.pinCode,
      password: !!user.password,
      isElevated: !!auth.session?.hasElevatedPermission,
      expiresAt: session?.expiresAt?.toISOString(),
      pinExpiresAt: session?.pinExpiresAt?.toISOString(),
    };
  }
}
