<?php

namespace Ekapusta\OAuth2Esia\Security\Signer;

use \BadMethodCallException;
use Ekapusta\OAuth2Esia\Security\Signer;
use Ekapusta\OAuth2Esia\Security\Signer\Exception\SignException;


class OpensslCli extends Signer implements \Lcobucci\JWT\Signer
{
    private $toolPath;
    
    private $tmpPath;

    
    public function __construct(
        $certificatePath,
        $privateKeyPath,
        $privateKeyPassword = null,
        $toolPath = 'openssl',
        $tmpPath = null
    ) {
        parent::__construct($certificatePath, $privateKeyPath, $privateKeyPassword);
        $this->toolPath = $toolPath;
        $this->tmpPath = $tmpPath;
    }

    /**
     * Create detached signature
     * @param string $message
     * @return false|string
     * @throws SignException
     */
    public function signCms($message)
    {
        return $this->runParameters([
            'smime -sign -binary -outform DER -noattr',
            '-signer '.escapeshellarg($this->certificatePath),
            '-inkey '.escapeshellarg($this->privateKeyPath),
            '-passin '.escapeshellarg('pass:'.$this->privateKeyPassword),
        ], $message);
    }

    /**
     * Generate OpenSSL command parameter list
     * @param array $parameters
     * @param mixed $input
     * @return false|string
     * @throws SignException
     */
    private function runParameters(array $parameters, $input)
    {
        array_unshift($parameters, $this->toolPath);

        return $this->run(implode(' ', $parameters), $input);
    }

    /**
     * Runs command with input from STDIN.
     * @param string $command
     * @param mixed $input
     * @return false|string
     * @throws SignException
     */
    private function run($command, $input)
    {
        $process = proc_open($command, [
            ['pipe', 'r'], // stdin
            ['pipe', 'w'], // stdout
            ['pipe', 'w'], // stderr
        ], $pipes);

        fwrite($pipes[0], $input);
        fclose($pipes[0]);

        $result = stream_get_contents($pipes[1]);
        fclose($pipes[1]);

        $errors = stream_get_contents($pipes[2]);
        fclose($pipes[2]);

        $code = proc_close($process);

        if (0 != $code) {
            $errors = trim($errors) ?: 'unknown';
            throw SignException::signFailedAsOf($errors, $code);
        }

        return $result;
    }
    
    /**
     * Returns random file in temporary folder with content
     * @param mixed $content
     * @return string
     */
    private function generateTemporaryFile($content)
    {
        $fileName = $this->tmpPath . DIRECTORY_SEPARATOR . uniqid("", true);
        file_put_contents($fileName, $content);
        return $fileName;
    }
    
    /**
     * (Lcobucci\JWT\Signer) Returns the algorithm id
     * @return string
     */
    public function getAlgorithmId()
    {
        return 'GOST3410_2012_256';
    }
    
    /**
     * (Lcobucci\JWT\Signer) Returns if the expected hash matches with the data and key
     * @param string $expected подпись
     * @param string $payload проверяемые данные
     * @param \Lcobucci\JWT\Signer\Key|string $key сертификат
     * @return boolean
     */
    public function verify($expected, $payload, $key)
    {
        $result = true;
        
        // extract public key from certificate
        $publicKey = $this->runParameters(['x509 -pubkey -noout'], $key->getContent());

        try {
            $publicKeyFile = $this->generateTemporaryFile($publicKey);
            $signFile = $this->generateTemporaryFile($expected);
            
            // check signature 
            $this->runParameters([
                'dgst -md_gost12_256',
                '-verify ' . escapeshellarg($publicKeyFile),
                '-signature ' . escapeshellarg($signFile),
            ], $payload);
        }
        
        catch(SignException $e) {
            $result = false;
        }
        
        finally {
            if (!empty($publicKeyFile)) {
                unlink($publicKeyFile);
            }
            if (!empty($signFile)) {
                unlink($signFile);
            }
        }
        
        return $result;
    }

    /**
     * (Lcobucci\JWT\Signer) Apply changes on headers according with algorithm
     * @param array $headers
     */
    public function modifyHeader(array &$headers)
    {
        throw new BadMethodCallException("modifyHeader not implemented");
    }

    /**
     * (Lcobucci\JWT\Signer) Returns a signature for given data
     * @param string $payload
     * @param \Lcobucci\JWT\Signer\Key|string $key
     * @throws BadMethodCallException
     */
    public function sign($payload, $key)
    {
        throw new BadMethodCallException("sign not implemented");
    }
}
