/*
 * ValidationFailureLog ORM model
 * Tracks all input validation failures for security monitoring
 */

export default class ValidationFailureLog {
    public id: number | null;
    public userId: number | null;
    public username: string | null;
    public fieldName: string;
    public fieldValue: string;
    public validationType: string;
    public errorMessage: string;
    public endpoint: string;
    public ipAddress: string;
    public userAgent: string;
    public timestamp: Date;

    constructor(
        id: number | null,
        userId: number | null,
        username: string | null,
        fieldName: string,
        fieldValue: string,
        validationType: string,
        errorMessage: string,
        endpoint: string,
        ipAddress: string,
        userAgent: string,
        timestamp?: Date
    ) {
        this.id = id;
        this.userId = userId;
        this.username = username;
        this.fieldName = fieldName;
        this.fieldValue = fieldValue;
        this.validationType = validationType;
        this.errorMessage = errorMessage;
        this.endpoint = endpoint;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.timestamp = timestamp || new Date();
    }

    /**
     * Get recent validation failure logs
     */
    static async getRecent(limit = 100): Promise<ValidationFailureLog[]> {
        const alasql = (await import('alasql')).default;
        
        try {
            const results = await alasql.promise(
                `SELECT * FROM validation_failure_logs ORDER BY timestamp DESC LIMIT ${limit}`
            );
            
            return results.map((row: any) => new ValidationFailureLog(
                row.id,
                row.userId,
                row.username,
                row.fieldName,
                row.fieldValue,
                row.validationType,
                row.errorMessage,
                row.endpoint,
                row.ipAddress,
                row.userAgent,
                new Date(row.timestamp)
            ));
        } catch (error) {
            console.error('Error fetching validation failure logs:', error);
            return [];
        }
    }

    /**
     * Get validation failure statistics
     */
    static async getStatistics(): Promise<{
        totalFailures: number;
        recentFailuresCount: number;
        failuresByType: Record<string, number>;
        failuresByField: Record<string, number>;
        failuresByEndpoint: Record<string, number>;
    }> {
        const alasql = (await import('alasql')).default;
        
        try {
            // Total failures
            const totalResult = await alasql.promise(
                'SELECT COUNT(*) as count FROM validation_failure_logs'
            );
            const totalFailures = totalResult[0]?.count || 0;

            // Recent failures (last 24 hours)
            const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
            const recentResult = await alasql.promise(
                `SELECT COUNT(*) as count FROM validation_failure_logs WHERE timestamp >= '${oneDayAgo}'`
            );
            const recentFailuresCount = recentResult[0]?.count || 0;

            // Failures by type
            const typeResults = await alasql.promise(
                'SELECT validationType, COUNT(*) as count FROM validation_failure_logs GROUP BY validationType ORDER BY count DESC'
            );
            const failuresByType: Record<string, number> = {};
            typeResults.forEach((row: any) => {
                failuresByType[row.validationType] = row.count;
            });

            // Failures by field
            const fieldResults = await alasql.promise(
                'SELECT fieldName, COUNT(*) as count FROM validation_failure_logs GROUP BY fieldName ORDER BY count DESC'
            );
            const failuresByField: Record<string, number> = {};
            fieldResults.forEach((row: any) => {
                failuresByField[row.fieldName] = row.count;
            });

            // Failures by endpoint
            const endpointResults = await alasql.promise(
                'SELECT endpoint, COUNT(*) as count FROM validation_failure_logs GROUP BY endpoint ORDER BY count DESC'
            );
            const failuresByEndpoint: Record<string, number> = {};
            endpointResults.forEach((row: any) => {
                failuresByEndpoint[row.endpoint] = row.count;
            });

            return {
                totalFailures,
                recentFailuresCount,
                failuresByType,
                failuresByField,
                failuresByEndpoint
            };
        } catch (error) {
            console.error('Error getting validation failure statistics:', error);
            return {
                totalFailures: 0,
                recentFailuresCount: 0,
                failuresByType: {},
                failuresByField: {},
                failuresByEndpoint: {}
            };
        }
    }

    /**
     * Initialize the validation failure logs table
     */
    static async initializeTable(): Promise<void> {
        const alasql = (await import('alasql')).default;
        
        try {
            console.log('Creating validation_failure_logs table...');
            await alasql.promise(`
                CREATE TABLE IF NOT EXISTS validation_failure_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    userId INTEGER,
                    username TEXT,
                    fieldName TEXT NOT NULL,
                    fieldValue TEXT,
                    validationType TEXT NOT NULL,
                    errorMessage TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    ipAddress TEXT NOT NULL,
                    userAgent TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            `);
            console.log('validation_failure_logs table created successfully');
        } catch (error) {
            console.error('Error initializing validation failure logs table:', error);
        }
    }

    /**
     * Create/save a validation failure log entry
     */
    async create(): Promise<void> {
        const alasql = (await import('alasql')).default;
        
        try {
            // Escape single quotes in string values to prevent SQL injection
            const escapedUsername = this.username ? this.username.replace(/'/g, '\'\'') : null;
            const escapedFieldValue = this.fieldValue.replace(/'/g, '\'\'');
            const escapedValidationType = this.validationType.replace(/'/g, '\'\'');
            const escapedErrorMessage = this.errorMessage.replace(/'/g, '\'\'');
            const escapedEndpoint = this.endpoint.replace(/'/g, '\'\'');
            const escapedIpAddress = this.ipAddress.replace(/'/g, '\'\'');
            const escapedUserAgent = this.userAgent ? this.userAgent.replace(/'/g, '\'\'') : null;
            
            const result = await alasql.promise(
                `INSERT INTO validation_failure_logs 
                (userId, username, fieldName, fieldValue, validationType, errorMessage, endpoint, ipAddress, userAgent, timestamp) 
                VALUES (${this.userId || 'NULL'}, ${escapedUsername ? `'${escapedUsername}'` : 'NULL'}, '${this.fieldName}', '${escapedFieldValue}', '${escapedValidationType}', '${escapedErrorMessage}', '${escapedEndpoint}', '${escapedIpAddress}', ${escapedUserAgent ? `'${escapedUserAgent}'` : 'NULL'}, '${this.timestamp.toISOString()}')`
            );
            
            if (result && Array.isArray(result) && result.length > 0) {
                this.id = result[0];
            }
        } catch (error) {
            console.error('Error creating validation failure log:', error);
            throw error;
        }
    }

    /**
     * Clean up old validation failure logs (older than 90 days)
     */
    static async cleanup(): Promise<void> {
        const alasql = (await import('alasql')).default;
        
        try {
            const cutoffDate = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(); // 90 days ago
            await alasql.promise(
                `DELETE FROM validation_failure_logs WHERE timestamp < '${cutoffDate}'`
            );
        } catch (error) {
            console.error('Error cleaning up validation failure logs:', error);
        }
    }
}
