import jwt from 'jsonwebtoken';
import express from 'express';
import Componentry from "@metric-im/componentry";
import * as Authentication from "./authentication.mjs";
import {readFileSync} from "node:fs";
import {resolve} from "path";
import crypto from 'crypto';
import { DomainConfig } from '@metric-im/administrate';
import dns from 'dns';
import { promisify } from 'util';
import { Site } from '@metric-im/administrate';
import { createHash, randomBytes } from 'crypto';

export default class AccountControl extends Componentry.Module {
  constructor(connector, options = {}) {
    super(connector, import.meta.url);
    this.userCollection = this.connector.db.collection('user');
    this.accountCollection = this.connector.db.collection('account');
    this.aclCollection = this.connector.db.collection('acl');
    this.pendingCollection = this.connector.db.collection('pending');
    this.package = JSON.parse(readFileSync(resolve('./package.json')).toString());
    this.accessRequestCount = 0;
    this.accessRequestWindowStart = Date.now();

    // Configuration options for multi-project support
    this.rootName = options.rootName || 'metric';  // Root name for config/DNS (e.g., 'rhonda', 'metric')
  }

  /**
   * Configure AccountControl with custom options
   * Use AccountControl.Options({rootName: 'rhonda'}) to customize the module
   * @param {Object} options - Configuration options
   * @param {string} options.rootName - Root name for domain config, DNS records, and session cookies
   * @returns {Class} Configured AccountControl subclass
   */
  static Options(options) {
    return class AccountControlOptions extends AccountControl {
      constructor(connector) {
        super(connector, options);
      }
      static get name() {
        return "AccountControl"
      }
    }
  }

  routes() {
    let router = express.Router();
    /**
     * Tests whether there is an active user session established
     */
    router.use(this.test.bind(this));
    /**
     * Provide an explicit test
     */
    router.get("/session/test", async (req, res) => {
      if (!req.account || !req.account.userId) res.status(401).send();
      else res.status(201).send();
    });
    /**
     * Get current user and account
     */
    router.get("/session/context", async (req, res) => {
      let context = {version: this.package.version || 'unknown', profile: process.env.PROFILE || 'production'};

      // Always include domain information
      const domain = Site.WashName(req.hostname);
      const config = new DomainConfig(this.rootName);
      config.setDomain(domain)
      const domainData = config.getDomain(domain);

      context.domain = {
        name: domain,
        autoRegister: config.domainData?.session?.autoRegister || false,
        verified: config.domainData?.verified || false,
        provider: config.domainData?.provider || null,
        rootName: this.rootName
      };

      if (req.account) {
        let accountRecord = await this.accountCollection.find({_id: req.account.id}).toArray();
        accountRecord = accountRecord[0];
        if (!accountRecord) res.status(404).send(`_id:${req.account.id} not found. ${JSON.stringify(context)}`);
        else res.json(Object.assign(
          context,
          {name: accountRecord.name || accountRecord._id},
          req.account));
      } else {
        res.json(context);
      }
    });
    /**
     * switch account
     */
    router.get("/session/switch/:id", async (req, res) => {
      try {
        if (req.account) {
          let access = await this.connector.acl.test.read({user: req.account.userId}, {account: req.params.id});
          if (access || req.account.super === true) {
            let accountData = {
              id: req.params.id,
              userId: req.account.userId,
              super: req.account.super,
              level: req.account.level
            }
            req.account = accountData;
            return res.json({status: 'success', account: accountData});
          }
        }
        res.status(401).json({status: 'error', message: 'not authorized'})
      } catch (e) {
        console.error(e);
        res.status(500).json({status: 'error', message: e.message});
      }
    });

    /**
     * Domain claiming routes for uninitialized domains
     */
    router.get("/claim", async (req, res) => {
      try {
        const domain = req.hostname;
        if (!domain) {
          return res.status(400).json({status: 'error', message: 'Domain not found'});
        }

        const config = new DomainConfig(this.rootName);
        const domainData = config.getDomain(domain);

        if (!domainData || !domainData.pending) {
          return res.status(400).json({status: 'error', message: 'No pending claim for this domain'});
        }

        // Accept address from query param (for unclaimed domains without sessions)
        const clientAddress = req.query.address;
        console.log(`[debug] Verification attempt for domain: ${domain}`);
        console.log(`[debug] Client address: ${clientAddress}`);
        console.log(`[debug] Stored challenge address: ${domainData.challenge_address}`);
        console.log(`[debug] Challenge token: ${domainData.challenge_token}`);

        if (!clientAddress) {
          return res.status(401).json({status: 'error', message: 'Client address not found'});
        }

        // Normalize addresses for comparison (case-insensitive)
        const normalizedClientAddress = clientAddress.toLowerCase();
        const normalizedChallengeAddress = domainData.challenge_address.toLowerCase();

        if (normalizedChallengeAddress !== normalizedClientAddress) {
          console.log(`[debug] Address mismatch: stored=${domainData.challenge_address}, current=${clientAddress}`);
          return res.status(403).json({status: 'error', message: 'Only the original requester can complete the claim'});
        }

        const resolveTxt = promisify(dns.resolveTxt);
        const records = await resolveTxt(`_${this.rootName}.${domain}`);
        const txtRecord = records.flat().find(record => record === domainData.challenge_token);

        if (!txtRecord) {
          return res.status(400).json({status: 'error', message: 'DNS TXT record not found or incorrect'});
        }

        console.log(`[debug] Domain claim completed: ${domain} by ${normalizedClientAddress} from ${req.ip}`);

        config.setDomain(domain);
        config.domainData.verified = true;
        config.domainData.admin_address = normalizedClientAddress;
        config.domainData.claimed_at = new Date().toISOString();
        config.domainData.verified_from_ip = req.ip; //TODO: multisite host has to pass real ip
        delete config.domainData.pending;
        delete config.domainData.challenge_token;
        delete config.domainData.challenge_address;
        delete config.domainData.challenge_requester_ip;
        config.save();

        // populate the database if necessary
        await this.connector.componentry.modules.ApplicationModule.testInitialize();

        res.json({status: 'success', message: 'Domain claimed successfully'});
      } catch (error) {
        console.error('Claim verification error:', error);
        res.status(500).json({status: 'error', message: error.message});
      }
    });

    router.get("/account/claim", async (req, res) => {
      try {
        const domain = req.hostname;
        if (!domain) {
          return res.status(400).json({status: 'error', message: 'Domain not found'});
        }

        const config = new DomainConfig(this.rootName);
        config.setDomain(domain);

        if (config.domainData && config.domainData.verified) {
          return res.status(400).json({status: 'error', message: 'Domain already claimed'});
        }

        // Return existing challenge if one exists
        if (config.domainData && config.domainData.pending && config.domainData.challenge_token) {
          return res.json(config.domainData.challenge_token);
        }
        res.json(null);
      } catch (error) {
        console.error('Challenge check error:', error);
        res.status(500).json({status: 'error', message: error.message});
      }
    });

    router.post("/account/claim", async (req, res) => {
      try {
        const domain = req.hostname;
        if (!domain) {
          return res.status(400).json({status: 'error', message: 'Domain not found'});
        }

        // Validate request origin to prevent domain claim spam
        const origin = req.get('origin') || req.get('referer');
        if (origin) {
          const originUrl = new URL(origin);
          if (originUrl.hostname !== domain) {
            return res.status(403).json({status: 'error', message: 'Request origin does not match domain'});
          }
        }

        // Accept wallet address from request body (unauthenticated during initial claim)
        // Security is enforced by DNS TXT record verification, not by wallet authentication here
        const clientAddress = req.body.clientAddress;
        if (!clientAddress) {
          return res.status(400).json({status: 'error', message: 'Client address required in request body'});
        }

        const providerConfig = req.body.provider;
        if (!providerConfig || !providerConfig.name || !providerConfig.chainId || !providerConfig.rpcUrl) {
          return res.status(400).json({status: 'error', message: 'Invalid provider configuration'});
        }

        const config = new DomainConfig(this.rootName);
        let domainData = config.getDomain(domain);

        if (domainData && domainData.verified) {
          return res.status(400).json({status: 'error', message: 'Domain already claimed'});
        }

        // Return existing challenge if one already exists (idempotent)
        if (domainData && domainData.pending && domainData.challenge_token) {
          console.log(`[debug] Returning existing challenge for domain: ${domain}`);
          return res.json(domainData.challenge_token);
        }

        const challengeToken = crypto.randomBytes(32).toString('hex');
        // Normalize address to lowercase for consistency
        const normalizedClientAddress = clientAddress.toLowerCase();

        // Audit log for security monitoring
        console.log(`[debug] Domain claim initiated: ${domain} by ${normalizedClientAddress} from ${req.ip} (${req.get('user-agent')})`);

        // Save to domain config
        config.setDomain(domain);
        config.domainData.pending = true;
        config.domainData.challenge_token = challengeToken;
        config.domainData.challenge_address = normalizedClientAddress;
        config.domainData.challenge_created = new Date().toISOString();
        config.domainData.challenge_requester_ip = req.ip;
        config.domainData.provider = providerConfig;

        console.log(`[debug] Saving challenge for domain: ${domain}`);
        console.log(`[debug] Challenge token: ${challengeToken}`);
        console.log(`[debug] Client address: ${clientAddress}`);
        config.save();
        console.log(`[debug] Successfully saved domain config for ${domain}`);

        // Also save provider config to Epistery domain config
        try {
          const episteryConfig = new DomainConfig('epistery');
          episteryConfig.setDomain(domain);
          episteryConfig.domainData.name = domain;
          episteryConfig.domainData.provider = {
            chainId: providerConfig.chainId,
            name: providerConfig.name,
            rpc: providerConfig.rpcUrl
          };
          episteryConfig.save();
          console.log(`Saved provider config to Epistery domain config: ${domain}`);
        } catch (episteryError) {
          console.error('Failed to save provider config to Epistery:', episteryError);
          // Don't fail the entire request if Epistery config save fails
        }

        res.json(challengeToken);

      } catch (error) {
        console.error('Challenge generation error:', error);
        res.status(500).json({status: 'error', message: error.message});
      }
    });

    /**
     * manager users and accounts
     */
    router.get("/user/:id?", async (req, res) => {
      try {
        let aggregation = [{$match: {}}, {$project: {hash: 0}}]
        if (req.params.id) aggregation[0].$match._id = req.params.id;
        if (req.query.acl) {
          aggregation.push({$lookup: {from: "acl", foreignField: "_id.user", localField: "_id", as: "__acl"}})
        }
        aggregation.push({$sort: {_id: 1}})
        let users = await this.userCollection.aggregate(aggregation).toArray();
        res.json(req.params.id ? users[0] : users);
      } catch (e) {
        console.error(e);
        res.status(500).json({status: 'error', message: e.message});
      }
    });
    router.get("/user/:userId/account/:accountId?", async (req, res) => {
      try {
        if (req.params.userId === req.account.userId || req.account.super) {
          let match = {user: req.params.userId};
          if (req.params.accountId) match.account = req.params.accountId;
          let acl = await this.aclCollection.find({user: req.params.userId}).sort({account: 1}).toArray();
          res.json(acl);
        } else {
          res.status(401).send();
        }
      } catch (e) {
        console.error(e);
        res.status(500).json({status: 'error', message: e.message});
      }
    });
    router.put("/user/:id", async (req, res) => {
      try {
        let user = await this.userCollection.findOne({_id: req.params.id});
        if ((!user && req.account.super === true) || (user._id === req.account.userId || req.account.super === true)) {
          let modifier = Object.keys(req.body).reduce((r, k) => {
            if (!['_id', '_created', '_createdBy', '_modified', 'hash', '__acl'].includes(k) && !k.startsWith('__')) {
              r.$set[k] = req.body[k];
            }
            return r;
          }, {
            $set: {_modified: new Date()},
            $setOnInsert: {_created: new Date(), _id: req.params.id},
            $unset: {__acl: 1}
          })
          await this.userCollection.updateOne({_id: req.params.id}, modifier, {upsert: true});
          // new users are automatically given read access to root.
          if (!user) {
            await this.connector.acl.assign.all({account: 'root'}, {user: req.params.id}, {level: 1});
          }
        } else {
          req.status(401).send();
        }
        res.status(204).send();
      } catch (e) {
        console.error(e);
        res.status(500).json({status: 'error', message: e.message});
      }
    });
    router.delete('/user/:id', async (req, res) => {
      try {
        if (req.account?.super === true) {
          await this.userCollection.deleteOne({_id: req.params.id});
          res.status(204).send();
        } else {
          res.status(401).json({status: "error", message: "Unauthorized"});
        }
      } catch (e) {
        console.error(e);
        res.status(500).json({status: 'error', message: e.message});
      }
    });
    /**
     * Generate the API KEY for the current account session.
     * This needs more thought to protect apikey access
     */
    router.get("/session/apikey", (req, res) => {
      if (req.account && req.account.id && req.account.level > 2) {
        let apikey = jwt.sign(
          {id: req.account.id, level: 2, super: false, ts: Date.now()},
          this.connector.profile.API_SECRET,
          {expiresIn: '365d'}
        );
        res.json({key: apikey});
      } else {
        res.status(404).send();
      }
    });
    router.get("/account/:id?", async (req, res) => {
      try {
        let resource = req.params.id ? {account: req.params.id} : "account";
        let access = await this.connector.acl.get.read({user: req.account.userId}, resource);
        let aggregation = [{$match: {}}]
        if (!req.account.super) aggregation[0].$match._id = {$in: access.map(a => a._id.account)};
        if (req.query.acl) {
          aggregation.push({$lookup: {from: "acl", foreignField: "_id.account", localField: "_id", as: "__acl"}})
        }
        aggregation.push({$sort: {_id: 1}})
        let accounts = await this.accountCollection.aggregate(aggregation).toArray();
        res.json(req.params.id ? accounts[0] : accounts);
      } catch (e) {
        console.error(e);
        res.status(500).json({status: 'error', message: e.message});
      }
    });
    router.put("/account/:id", async (req, res) => {
      try {
        let account = await this.accountCollection.findOne({_id: req.params.id});
        if (account) {
          let access = await this.connector.acl.test.owner({user: req.account.userId}, {account: req.params.id});
          if (access || req.account.super === true) {
            // note that __acl is explicitly removed as cleanup.
            let modifier = Object.keys(req.body).reduce((r, k) => {
              if (!['_id', '_created', '_createdBy', '_modified', '__acl'].includes(k)) {
                r.$set[k] = req.body[k];
              }
              return r;
            }, {$set: {_modified: new Date()}, $unset: {__acl: 1}});
            await this.accountCollection.updateOne({_id: account._id}, modifier, {upsert: true});
          } else {
            return res.status(401).json({status: "error", message: "Unauthorized"});
          }
        } else {
          req.body._created = new Date;
          req.body._modified = req.body.created;
          req.body._createdBy = req.account.userId;
          req.body.options = {};
          await this.accountCollection.insertOne(req.body);
        }
        res.status(204).send();
      } catch (e) {
        console.error(e);
        res.status(500).json({status: 'error', message: e.message});
      }
    });
    router.put('/acl/:entity/:id', async (req, res) => {
      try {
        if (req.account.super || await this.connector.acl.test.owner(
          {account: req.account.id},
          {[req.params.entity]: req.params.id})) {
          let records = Array.isArray(req.body) ? req.body : [req.body];
          if (records.length > 0) {
            await this.connector.acl.assign.all({[req.params.entity]: req.params.id}, records);
          }
          res.status(204).send();
        } else {
          res.status(401).send();
        }
      } catch (e) {
        console.error(e);
        res.status(500).json({status: 'error', message: e.message});
      }
    })
    router.delete('/account/:id', async (req, res) => {
      try {
        if (req.account.super === true) {
          await this.accountCollection.deleteOne({_id: req.params.id});
          res.status(204).send();
        } else {
          res.status(401).json({status: "error", message: "Unauthorized"});
        }
      } catch (e) {
        console.error(e);
        res.status(500).json({status: 'error', message: e.message});
      }
    });

    /**
     * Pending access requests
     */
    // POST - users without accounts can request access (no req.account required)
    router.post("/pending/access", async (req, res) => {
      try {
        // Verify client wallet ownership using signature (same pattern as epistery key exchange)
        const { clientAddress, proofMessage, signature, message } = req.body;

        if (!clientAddress || !proofMessage || !signature) {
          return res.status(400).json({status: 'error', message: 'Missing required fields for proof of ownership'});
        }

        // Verify the signature matches the claimed address
        let ethers;
        try {
          ethers = await import('ethers');
        } catch (e) {
          console.error('[pending] Failed to load ethers:', e);
          return res.status(500).json({status: 'error', message: 'Server configuration error'});
        }

        const recoveredAddress = ethers.utils.verifyMessage(proofMessage, signature);
        if (recoveredAddress.toLowerCase() !== clientAddress.toLowerCase()) {
          console.log('[pending] Signature verification failed:', {
            claimed: clientAddress,
            recovered: recoveredAddress
          });
          return res.status(401).json({status: 'error', message: 'Invalid signature - wallet ownership proof failed'});
        }

        console.log('[pending] Signature verified for address:', clientAddress);

        // Rate limiting: 10 requests per minute globally
        const now = Date.now();
        const oneMinute = 60 * 1000;
        if (now - this.accessRequestWindowStart > oneMinute) {
          // Reset window
          this.accessRequestWindowStart = now;
          this.accessRequestCount = 0;
        }

        if (this.accessRequestCount >= 10) {
          console.log('[pending] Rate limit exceeded');
          return res.status(429).json({status: 'error', message: 'Too many requests. Please try again later.'});
        }

        this.accessRequestCount++;

        // Check pending queue limit: reject if 100+ pending requests
        const pendingCount = await this.pendingCollection.countDocuments({
          requestType: 'createUser',
          _deleted: {$exists: false}
        });

        if (pendingCount >= 100) {
          console.log(`[pending] Queue full: ${pendingCount} pending requests`);
          return res.status(503).json({status: 'error', message: 'Please try again later.'});
        }

        // Check if user already exists
        const normalizedAddress = clientAddress.toLowerCase();
        const existingUser = await this.userCollection.findOne({address: normalizedAddress});
        if (existingUser) {
          return res.status(400).json({status: 'error', message: 'User already exists for this address'});
        }

        // Validate message
        const userMessage = message || '';
        if (userMessage.length > 500) {
          return res.status(400).json({status: 'error', message: 'Message too long (max 500 characters)'});
        }

        // Check if request already exists (including deleted ones)
        const existingRequest = await this.pendingCollection.findOne({_id: normalizedAddress});
        if (existingRequest) {
          if (existingRequest._deleted) {
            return res.status(403).json({status: 'error', message: 'Previous request was rejected'});
          }
          return res.status(400).json({status: 'error', message: 'Request already pending'});
        }

        // Create pending request
        const requestData = {
          _id: normalizedAddress,
          requestType: 'createUser',
          address: normalizedAddress,
          message: userMessage,
          _created: new Date()
        };

        await this.pendingCollection.insertOne(requestData);

        console.log(`[pending] Access request created for ${normalizedAddress}`);
        res.json({status: 'success', message: 'Access request submitted'});
      } catch (e) {
        console.error(e);
        res.status(500).json({status: 'error', message: e.message});
      }
    });

    // GET - admin only
    router.get("/pending/access", async (req, res) => {
      try {
        // Only super users can view pending requests
        if (!req.account || req.account.super !== true) {
          return res.status(401).json({status: 'error', message: 'Unauthorized'});
        }

        // Get all non-deleted pending requests
        const requests = await this.pendingCollection.find({
          requestType: 'createUser',
          _deleted: {$exists: false}
        }).sort({_created: -1}).toArray();

        res.json(requests);
      } catch (e) {
        console.error(e);
        res.status(500).json({status: 'error', message: e.message});
      }
    });

    router.post("/pending/access/:address/accept", async (req, res) => {
      try {
        // Only super users can accept requests
        if (!req.account || req.account.super !== true) {
          return res.status(401).json({status: 'error', message: 'Unauthorized'});
        }

        const normalizedAddress = req.params.address.toLowerCase();
        const pendingRequest = await this.pendingCollection.findOne({_id: normalizedAddress});

        if (!pendingRequest) {
          return res.status(404).json({status: 'error', message: 'Request not found'});
        }

        if (pendingRequest._deleted) {
          return res.status(400).json({status: 'error', message: 'Request already processed'});
        }

        // Check if user already exists
        const existingUser = await this.userCollection.findOne({address: normalizedAddress});
        if (existingUser) {
          // Mark request as deleted since user exists
          await this.pendingCollection.updateOne(
            {_id: normalizedAddress},
            {$set: {_deleted: new Date(), _deletedBy: req.account.userId}}
          );
          return res.status(400).json({status: 'error', message: 'User already exists'});
        }

        // Create the user (similar to PUT /user/:id endpoint)
        const userId = normalizedAddress;
        await this.userCollection.insertOne({
          _id: userId,
          address: normalizedAddress,
          _created: new Date(),
          _createdBy: req.account.userId
        });

        // Give user read access to root account
        await this.connector.acl.assign.all({account: 'root'}, {user: userId}, {level: 1});

        // Soft delete the pending request
        await this.pendingCollection.updateOne(
          {_id: normalizedAddress},
          {$set: {_deleted: new Date(), _deletedBy: req.account.userId, _accepted: true}}
        );

        console.log(`[pending] Access request accepted for ${normalizedAddress} by ${req.account.userId}`);
        res.json({status: 'success', message: 'User created successfully'});
      } catch (e) {
        console.error(e);
        res.status(500).json({status: 'error', message: e.message});
      }
    });

    router.post("/pending/access/:address/reject", async (req, res) => {
      try {
        // Only super users can reject requests
        if (!req.account || req.account.super !== true) {
          return res.status(401).json({status: 'error', message: 'Unauthorized'});
        }

        const normalizedAddress = req.params.address.toLowerCase();
        const pendingRequest = await this.pendingCollection.findOne({_id: normalizedAddress});

        if (!pendingRequest) {
          return res.status(404).json({status: 'error', message: 'Request not found'});
        }

        if (pendingRequest._deleted) {
          return res.status(400).json({status: 'error', message: 'Request already processed'});
        }

        // Soft delete the request
        await this.pendingCollection.updateOne(
          {_id: normalizedAddress},
          {$set: {_deleted: new Date(), _deletedBy: req.account.userId, _rejected: true}}
        );

        console.log(`[pending] Access request rejected for ${normalizedAddress} by ${req.account.userId}`);
        res.json({status: 'success', message: 'Request rejected'});
      } catch (e) {
        console.error(e);
        res.status(500).json({status: 'error', message: e.message});
      }
    });
    router.post("/pending/access/automatic", async (req, res) => {
        try {
            // autoRegister must be set to true in the domain config
            const config = new DomainConfig(this.rootName);
            const domain = req.hostname;
            const domainData = config.getDomain(domain);
            if (domainData.session?.autoRegister === true) {
                // Verify client wallet ownership using signature (same pattern as epistery key exchange)
                const { clientAddress, proofMessage, signature } = req.body;

                if (!clientAddress || !proofMessage || !signature) {
                    return res.status(400).json({status: 'error', message: 'Missing required fields for proof of ownership'});
                }
                // Verify the signature matches the claimed address
                let ethers;
                try {
                    ethers = await import('ethers');
                } catch (e) {
                    console.error('[pending] Failed to load ethers:', e);
                    return res.status(500).json({status: 'error', message: 'Server configuration error'});
                }

                const recoveredAddress = ethers.utils.verifyMessage(proofMessage, signature);
                if (recoveredAddress.toLowerCase() !== clientAddress.toLowerCase()) {
                    console.log('[pending] Signature verification failed:', {
                        claimed: clientAddress,
                        recovered: recoveredAddress
                    });
                    return res.status(401).json({status: 'error', message: 'Invalid signature - wallet ownership proof failed'});
                }

                console.log('[pending] Signature verified for address:', clientAddress);

                // Rate limiting: 10 requests per minute globally
                const now = Date.now();
                const oneMinute = 60 * 1000;
                if (now - this.accessRequestWindowStart > oneMinute) {
                    // Reset window
                    this.accessRequestWindowStart = now;
                    this.accessRequestCount = 0;
                }

                if (this.accessRequestCount >= 10) {
                    console.log('[pending] Rate limit exceeded');
                    return res.status(429).json({status: 'error', message: 'Too many requests. Please try again later.'});
                }

                this.accessRequestCount++;

                // Check if user already exists
                const normalizedAddress = clientAddress.toLowerCase();
                const existingUser = await this.userCollection.findOne({address: normalizedAddress});
                if (existingUser) {
                    return res.status(400).json({status: 'error', message: 'User already exists for this address'});
                }
                const userId = normalizedAddress;
                await this.userCollection.insertOne({
                    _id: userId,
                    address: normalizedAddress,
                    _created: new Date(),
                    _createdBy: 'system'
                });

                // Give user read access to root account
                await this.connector.acl.assign.all({account: 'root'}, {user: userId}, {level: 1});

                res.json({status: 'success', message: 'Access request submitted'});
            } else {
                return res.status(400).json({status: 'error', message: 'Unauthorized'});
            }

        } catch (e) {
            console.error(e);
            res.status(500).json({status: 'error', message: e.message});
        }
    });

    return router;
  }

  /**
   * Middleware to test authentication using session tokens or fresh epistery auth
   * First checks for valid session token in cookies
   * If fresh epistery client is available, creates account and sets session cookie
   * If no valid session, continues without account - dow      try {
        // Verify client wallet ownership using signature (same pattern as epistery key exchange)
        const { clientAddress, proofMessage, signature, message } = req.body;

        if (!clientAddress || !proofMessage || !signature) {
          return res.status(400).json({status: 'error', message: 'Missing required fields for proof of ownership'});
        }

        // Verify the signature matches the claimed address
        let ethers;
        try {
          ethers = await import('ethers');
        } catch (e) {
          console.error('[pending] Failed to load ethers:', e);
          return res.status(500).json({status: 'error', message: 'Server configuration error'});
        }

        const recoveredAddress = ethers.utils.verifyMessage(proofMessage, signature);
        if (recoveredAddress.toLowerCase() !== clientAddress.toLowerCase()) {
          console.log('[pending] Signature verification failed:', {
            claimed: clientAddress,
            recovered: recoveredAddress
          });
          return res.status(401).json({status: 'error', message: 'Invalid signature - wallet ownership proof failed'});
        }

        console.log('[pending] Signature verified for address:', clientAddress);

        // Rate limiting: 10 requests per minute globally
        const now = Date.now();
        const oneMinute = 60 * 1000;
        if (now - this.accessRequestWindowStart > oneMinute) {
          // Reset window
          this.accessRequestWindowStart = now;
          this.accessRequestCount = 0;
        }

        if (this.accessRequestCount >= 10) {
          console.log('[pending] Rate limit exceeded');
          return res.status(429).json({status: 'error', message: 'Too many requests. Please try again later.'});
        }

        this.accessRequestCount++;

        // Check pending queue limit: reject if 100+ pending requests
        const pendingCount = await this.pendingCollection.countDocuments({
          requestType: 'createUser',
          _deleted: {$exists: false}
        });

        if (pendingCount >= 100) {
          console.log(`[pending] Queue full: ${pendingCount} pending requests`);
          return res.status(503).json({status: 'error', message: 'Please try again later.'});
        }

        // Check if user already exists
        const normalizedAddress = clientAddress.toLowerCase();
        const existingUser = await this.userCollection.findOne({address: normalizedAddress});
        if (existingUser) {
          return res.status(400).json({status: 'error', message: 'User already exists for this address'});
        }

        // Validate message
        const userMessage = message || '';
        if (userMessage.length > 500) {
          return res.status(400).json({status: 'error', message: 'Message too long (max 500 characters)'});
        }

        // Check if request already exists (including deleted ones)
        const existingRequest = await this.pendingCollection.findOne({_id: normalizedAddress});
        if (existingRequest) {
          if (existingRequest._deleted) {
            return res.status(403).json({status: 'error', message: 'Previous request was rejected'});
          }
          return res.status(400).json({status: 'error', message: 'Request already pending'});
        }

        // Create pending request
        const requestData = {
          _id: normalizedAddress,
          requestType: 'createUser',
          address: normalizedAddress,
          message: userMessage,
          _created: new Date()
        };

        await this.pendingCollection.insertOne(requestData);

        console.log(`[pending] Access request created for ${normalizedAddress}`);
        res.json({status: 'success', message: 'Access request submitted'});
      } catch (e) {
        console.error(e);
        res.status(500).json({status: 'error', message: e.message});
      }
nstream services will be denied
   *
   * @param req
   * @param res
   * @param next
   * @returns {Promise<void>}
   */
  async test(req, res, next) {
    try {
      if (!req.account) {
        const domain = req.hostname;

        // Try to get account from session token (cookie-based session)
        const sessionCookieName = `_${this.rootName}_session`;
        if (req.cookies && req.cookies[sessionCookieName]) {
          const accountFromToken = this.validateSessionToken(req.cookies[sessionCookieName], domain);
          if (accountFromToken) {
            console.log('[auth] Session token valid, account restored:', accountFromToken.userId);
            req.account = accountFromToken;
          } else {
            console.log('[auth] Session token invalid or expired');
          }
        }

        // TODO: Consider more robust bot auth (see validateBotAuth method for details)
        // Format: Authorization: Bot <base64-json>
        // Verifies signature matches address, then looks up system account
        // This provides programmatic access for bots/agents/systems without browser-based Epistery
        if (!req.account && req.headers.authorization?.startsWith('Bot ')) {
          console.log('[auth] Bot authorization header detected');
          const botAuth = await this.validateBotAuth(req.headers.authorization.substring(4), domain);
          if (botAuth) {
            console.log('[auth] Bot authenticated:', botAuth.userId);
            req.account = botAuth;
          }
        }

        // Note: req.episteryClient session creation is handled by postMint() middleware
      }
      next();
    } catch (e) {
      // on any failure, account won't be set. Services choose whether to reply or reject
      req.account = null;
      next();
    }
  }

  async assignAcl(account) {
    if (!account.acl) {
      let result = await this.connector.acl.get.all({account: account.id}, null);
      account.acl = result.reduce((r, record) => {
        for (let key of Object.keys(record._id)) {
          if (key !== 'account') r[key] = {[key]: {[record._id[key]]: record.level}};
        }
        return r;
      }, {})
    }
  }

  generateSessionToken(accountData, domain) {
    // Get session configuration (default 60 minutes expiration)
    const config = new DomainConfig(this.rootName);
    const domainData = config.getDomain(domain);

    // Ensure session config exists with defaults
    if (!domainData.session) {
      config.setDomain(domain);
      config.domainData.session = {
        tokenExpiration: 60, // default 1 hour
        hashKey: randomBytes(32).toString('hex') // generate random hash key
      };
      config.save();
    }

    // Generate hash key if not present
    if (!domainData.session.hashKey) {
      config.setDomain(domain);
      config.domainData.session.hashKey = randomBytes(32).toString('hex');
      config.save();
    }

    const now = Date.now();
    const expirationMinutes = domainData.session.tokenExpiration || 60;
    const expiresAt = now + (expirationMinutes * 60 * 1000);

    const tokenData = {
      account: accountData, // Store the complete account object
      domain,
      createdAt: now,
      expiresAt
    };

    // Create token by combining tokenData with hash key
    const tokenString = JSON.stringify(tokenData);
    const hash = createHash('sha256');
    hash.update(tokenString + domainData.session.hashKey);
    const signature = hash.digest('hex');

    // Encode token as base64: tokenData + signature
    const token = Buffer.from(JSON.stringify({ ...tokenData, signature })).toString('base64');

    return token;
  }

  /**
   * Set session cookie for authenticated user
   * Encapsulates session cookie name and configuration details
   * @param {Object} accountData - Account data to store in session
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  setSessionCookie(accountData, req, res) {
    const sessionToken = this.generateSessionToken(accountData, req.hostname);
    const cookieName = `_${this.rootName}_session`;

    res.cookie(cookieName, sessionToken, {
      httpOnly: true,
      secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
      sameSite: 'strict',
      path: '/',
      maxAge: 60 * 60 * 1000  // 1 hour
    });

    return sessionToken;
  }

  validateSessionToken(token, domain) {
    try {
      const config = new DomainConfig(this.rootName);
      const domainData = config.getDomain(domain);

      if (!domainData.session?.hashKey) {
        return null;
      }

      // Decode token
      const tokenPayload = JSON.parse(Buffer.from(token, 'base64').toString());
      const { signature, ...tokenData } = tokenPayload;

      // Verify token structure
      if (!tokenData.account || !tokenData.domain || !tokenData.createdAt || !tokenData.expiresAt) {
        return null;
      }

      // Verify domain matches
      if (tokenData.domain !== domain) {
        return null;
      }

      // Verify token hasn't expired
      if (Date.now() > tokenData.expiresAt) {
        return null;
      }

      // Verify signature
      const tokenString = JSON.stringify(tokenData);
      const hash = createHash('sha256');
      hash.update(tokenString + domainData.session.hashKey);
      const expectedSignature = hash.digest('hex');

      if (signature === expectedSignature) {
        return tokenData.account; // Return the account object from token
      }

      return null;

    } catch (error) {
      console.error('Token validation error:', error);
      return null;
    }
  }

  /**
   * Validate bot authentication via Authorization header
   * Format: Authorization: Bot <base64-json>
   * Where base64-json decodes to: {address, signature, message}
   *
   * TODO: Consider more robust implementation:
   * - Message should include timestamp/nonce to prevent replay attacks
   * - Consider JWT-based tokens for bots instead of per-request signatures
   * - Rate limiting for bot accounts
   *
   * @param {string} authHeader - Base64-encoded JSON with {address, signature, message}
   * @param {string} domain - Current domain
   * @returns {Object|null} Account object if valid, null otherwise
   */
  async validateBotAuth(authHeader, domain) {
    try {
      // Parse authorization header - expect base64-encoded JSON
      let address, signature, message;

      try {
        const decoded = Buffer.from(authHeader, 'base64').toString('utf8');
        const payload = JSON.parse(decoded);
        address = payload.address;
        signature = payload.signature;
        message = payload.message;
      } catch (e) {
        console.log('[auth] Bot auth: Invalid format, failed to decode payload');
        return null;
      }

      if (!address || !signature || !message) {
        console.log('[auth] Bot auth: Missing required fields');
        return null;
      }

      // Verify signature using ethers (loaded from epistery)
      let ethers;
      try {
        ethers = await import('ethers');
      } catch (e) {
        console.error('[auth] Bot auth: Failed to load ethers:', e);
        return null;
      }

      // Verify the signature
      const recoveredAddress = ethers.utils.verifyMessage(message, signature);
      if (recoveredAddress.toLowerCase() !== address.toLowerCase()) {
        console.log('[auth] Bot auth: Signature verification failed');
        return null;
      }

      console.log('[auth] Bot auth: Signature verified for address:', address);

      // Look up user account - must be marked as system account
      const userAccount = await this.userCollection.findOne({
        address: address.toLowerCase()
      });

      if (!userAccount) {
        console.log('[auth] Bot auth: No user found for address:', address);
        return null;
      }

      // Check if this is a system/bot account (optional security check)
      if (userAccount.options?.systemAccount !== true) {
        console.log('[auth] Bot auth: Account is not marked as system account:', address);
        // Allow it anyway for now, but log the warning
      }

      // Get account access via ACL
      const accessibleAccounts = await this.connector.acl.get.all({user: userAccount._id}, 'account');
      const access = accessibleAccounts[0];

      if (!access) {
        console.log('[auth] Bot auth: No account access found for user:', userAccount._id);
        return null;
      }

      const accountData = {
        id: access._id.account,
        userId: userAccount._id,
        super: userAccount.options?.super || false,
        level: access.level || 0,
        address: address.toLowerCase()
      };

      console.log('[auth] Bot authenticated successfully:', {
        userId: accountData.userId,
        account: accountData.id,
        level: accountData.level
      });

      return accountData;

    } catch (e) {
      console.error('[auth] Bot auth validation error:', e);
      return null;
    }
  }

  static get Authentication() {
    return Authentication;
  }
}

// Backward compatibility export for projects still using "AccountServer" name
export { AccountControl as AccountServer };
