import express,{type Request,type Response,type NextFunction,type Application} from 'express';
import crypto from 'crypto';
import {fileURLToPath} from 'url';
import path from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app:Application = express();
const port:number=3000;

app.use(express.urlencoded({ extended: false }));
app.set('view engine','ejs');
app.set('views',path.join(__dirname,'../','views'));

app.get('/',async(req:Request,res:Response,next:NextFunction):Promise<void>=>{
    try {
        res.render('index',{
            message:null,
            error:null
        });
    } catch (error) {
        res.status(500).render('index',{
            message:null,
            error:`Error fetching the UI page:${error instanceof Error ? error.message:error}`
        });
    }
});

app.post('/',async(req:Request,res:Response,next:NextFunction):Promise<void>=>{
    const {privatekey,encryptionkey}:{privatekey:string,encryptionkey:string} = req.body;
    try {
        const encryptedData:string = privatekey.toString().trim();
        const secretKey:string = encryptionkey.toString().trim();
        const response = await decryptKey(encryptedData,secretKey);
        res.render('index',{
            message:response,
            error:null
        });
    } catch (error) {
        res.status(500).render('index',{message:null,error:`Error decrypting the key:${error instanceof Error ? error.message:error}`});
    }
});


app.listen(port,()=>console.log('On'));



export async function decryptKey(encryptedData: string,secretKey:string): Promise<string> {
    try {
        const algorithm = 'aes-256-cbc';
        
        
        if (!secretKey) {
            throw new Error('Missing encryption key in environment variables');
        }

  
        const keyBuffer = Buffer.from(secretKey, 'hex');
        if (keyBuffer.length !== 32) {
            throw new Error('Encryption key must be 32 bytes (64 hex characters)');
        }

 
        const parts = encryptedData.split(':');
        if (parts.length !== 2) {
            throw new Error('Invalid encrypted data format');
        }

        const iv = Buffer.from(parts[0], 'hex');
        const encryptedText = parts[1];


        const decipher = crypto.createDecipheriv(algorithm, keyBuffer, iv);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } catch (error) {
        console.error('Decryption failed:', error);
        throw new Error('Failed to decrypt data');
    }
}