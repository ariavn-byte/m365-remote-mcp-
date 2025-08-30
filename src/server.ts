import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express, { Request, Response, NextFunction } from 'express';
import logger, { enableConsoleLogging } from './logger.js';
import { registerAuthTools } from './auth-tools.js';
import { registerGraphTools } from './graph-tools.js';
import GraphClient from './graph-client.js';
import AuthManager from './auth.js';
import type { CommandOptions } from './cli.ts';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import type { IncomingMessage, ServerResponse } from 'http';

// Helper to get the directory name in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface EndpointInfo {
  toolName: string;
  method: string;
  pathPattern: string;
}

class MicrosoftGraphServer {
  private authManager: AuthManager;
  private options: CommandOptions;
  private graphClient: GraphClient;
  private server: McpServer | null;
  private version: string = '0.0.0';

  constructor(authManager: AuthManager, options: CommandOptions = {}) {
    this.authManager = authManager;
    this.options = options;
    this.graphClient = new GraphClient(authManager);
    this.server = null;
  }

  async initialize(version: string): Promise<void> {
    this.version = version;
    this.server = new McpServer({
      name: 'Microsoft365MCP',
      version,
    });

    const shouldRegisterAuthTools = !this.options.http || this.options.enableAuthTools;
    if (shouldRegisterAuthTools) {
      registerAuthTools(this.server, this.authManager);
    }
    registerGraphTools(
      this.server,
      this.graphClient,
      this.options.readOnly,
      this.options.enabledTools,
      this.options.orgMode
    );
  }

  private generateOpenAPISpec(req: Request): Record<string, unknown> {
    const serverUrl = `${req.protocol}://${req.get('host')}`;
    const endpointsData: EndpointInfo[] = JSON.parse(
      fs.readFileSync(path.join(__dirname, 'endpoints.json'), 'utf8')
    );

    const paths = endpointsData.reduce((acc: Record<string, unknown>, endpoint: EndpointInfo) => {
      const path = `/mcp/${endpoint.toolName}`; // Create a unique path for each tool
      if (!acc[path]) {
        acc[path] = {};
      }
      // Assuming all tool calls are POST as per MCP over HTTP spec
      (acc[path] as Record<string, unknown>)['post'] = {
        summary: endpoint.toolName,
        description: `Executes the ${endpoint.toolName} tool. Path from Graph API: ${endpoint.method.toUpperCase()} ${endpoint.pathPattern}`,
        operationId: endpoint.toolName,
        tags: ['Microsoft Graph'],
        security: [{ bearerAuth: [] }],
        requestBody: {
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  // Define a generic body for MCP requests
                  jsonrpc: { type: 'string', example: '2.0' },
                  method: { type: 'string', example: endpoint.toolName },
                  params: { type: 'object' },
                  id: { type: 'string' },
                },
              },
            },
          },
        },
        responses: {
          '200': {
            description: 'Successful tool execution response',
          },
        },
      };
      return acc;
    }, {});

    return {
      openapi: '3.0.0',
      info: {
        title: 'Microsoft 365 MCP Server',
        version: this.version,
        description: 'A server providing tools to interact with Microsoft 365 APIs.',
      },
      servers: [
        {
          url: serverUrl,
        },
      ],
      components: {
        securitySchemes: {
          bearerAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'API-KEY',
          },
        },
      },
      paths,
    };
  }

  async start(): Promise<void> {
    if (this.options.v) {
      enableConsoleLogging();
    }

    logger.info('Microsoft 365 MCP Server starting...');

    if (this.options.readOnly) {
      logger.info('Server running in READ-ONLY mode. Write operations are disabled.');
    }

    if (this.options.http) {
      const port = parseInt(
        process.env.PORT || (typeof this.options.http === 'string' ? this.options.http : '3000'),
        10
      );

      const app = express();
      app.use(express.json());

      app.use((req, res, next: NextFunction) => {
        res.header('Access-Control-Allow-Origin', '*');
        res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.header(
          'Access-Control-Allow-Headers',
          'Origin, X-Requested-With, Content-Type, Accept, Authorization'
        );
        if (req.method === 'OPTIONS') {
          res.sendStatus(200);
          return;
        }
        next();
      });

      // Simple Bearer Token Auth Middleware
      const apiKeys = (process.env.MCP_SERVER_API_KEYS || '').split(',').filter(Boolean);
      if (apiKeys.length === 0) {
        logger.warn('Warning: MCP_SERVER_API_KEYS is not set. The server is unprotected.');
      }

      const simpleBearerAuthMiddleware = (req: Request, res: Response, next: NextFunction) => {
        if (apiKeys.length === 0) {
          return next(); // No keys configured, allow access
        }
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return res.status(401).json({ error: 'Unauthorized: Missing Bearer token' });
        }
        const token = authHeader.substring(7);
        if (!apiKeys.includes(token)) {
          return res.status(403).json({ error: 'Forbidden: Invalid API Key' });
        }
        next();
      };

      // OpenAPI Spec Endpoint
      app.get('/openapi.json', (req, res) => {
        try {
          const spec = this.generateOpenAPISpec(req);
          res.json(spec);
        } catch (error) {
          logger.error('Error generating OpenAPI spec:', error);
          res.status(500).json({ error: 'Failed to generate OpenAPI spec' });
        }
      });

      // All tool calls now go to a single MCP endpoint
      const mcpHandler = async (req: Request, res: Response) => {
        try {
          const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: undefined, // Stateless mode
          });
          res.on('close', () => transport.close());
          await this.server!.connect(transport);
          // The MCP SDK handles both GET and POST appropriately via handleRequest
          await transport.handleRequest(req as IncomingMessage, res as ServerResponse, req.body);
        } catch (error) {
          logger.error(`Error handling MCP ${req.method} request:`, error);
          if (!res.headersSent) {
            res.status(500).json({
              jsonrpc: '2.0',
              error: { code: -32603, message: 'Internal server error' },
              id: null,
            });
          }
        }
      };

      // Protect the single /mcp endpoint
      app.use('/mcp', simpleBearerAuthMiddleware, mcpHandler);

      // Health check endpoint
      app.get('/', (req, res) => {
        res.send('Microsoft 365 MCP Server is running');
      });

      app.listen(port, () => {
        logger.info(`Server listening on HTTP port ${port}`);
        logger.info(`  - MCP endpoint: http://localhost:${port}/mcp`);
        logger.info(`  - OpenAPI Spec: http://localhost:${port}/openapi.json`);
      });
    } else {
      const transport = new StdioServerTransport();
      await this.server!.connect(transport);
      logger.info('Server connected to stdio transport');
    }
  }
}

export default MicrosoftGraphServer;
