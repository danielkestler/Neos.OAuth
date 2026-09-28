<?php
declare(strict_types=1);

namespace Neos\OAuth\Tests\Functional\Infrastructure;

use Neos\Flow\Tests\FunctionalTestCase;
use Neos\OAuth\Infrastructure\League\KeyManager;
use Neos\Utility\Files;
use PHPUnit\Framework\Attributes\Test;

class KeyManagerTest extends FunctionalTestCase
{
    private string $directory;

    protected function setUp(): void
    {
        parent::setUp();
        $this->directory = FLOW_PATH_DATA . 'Temporary/Testing/Neos.OAuth.KeyManagerTest-' . bin2hex(random_bytes(4));
    }

    protected function tearDown(): void
    {
        Files::removeDirectoryRecursively($this->directory);
        parent::tearDown();
    }

    #[Test]
    public function generatesMissingKeyFilesOnFirstUse(): void
    {
        $keyManager = $this->keyManager();

        $keyManager->getPrivateKey();

        foreach (['private.key', 'public.key', 'encryption.key'] as $file) {
            self::assertFileExists($this->directory . '/' . $file);
            self::assertSame('600', decoct(fileperms($this->directory . '/' . $file) & 0777), $file);
        }
        self::assertStringStartsWith('-----BEGIN PUBLIC KEY-----', $keyManager->getPublicKey()->getKeyContents());
        $keyManager->getEncryptionKey();
    }

    #[Test]
    public function doesNotReplaceAPartialSetOfKeys(): void
    {
        $keyManager = $this->keyManager();
        $keyManager->getPrivateKey();
        unlink($this->directory . '/public.key');
        $privateKey = file_get_contents($this->directory . '/private.key');

        try {
            $keyManager->getPublicKey();
            self::fail('Expected an exception');
        } catch (\RuntimeException $exception) {
            self::assertSame(1790100016, $exception->getCode());
        }
        self::assertSame($privateKey, file_get_contents($this->directory . '/private.key'));
    }

    #[Test]
    public function usesConfiguredKeysInsteadOfFiles(): void
    {
        $source = $this->keyManager();
        $source->getPrivateKey();
        $keyManager = $this->keyManager([
            'privateKey' => file_get_contents($this->directory . '/private.key'),
            'publicKey' => file_get_contents($this->directory . '/public.key'),
            'encryptionKey' => file_get_contents($this->directory . '/encryption.key'),
            'privateKeyPath' => $this->directory . '/unused/private.key',
            'publicKeyPath' => $this->directory . '/unused/public.key',
            'encryptionKeyPath' => $this->directory . '/unused/encryption.key',
        ]);

        self::assertTrue($keyManager->keysAreConfigured());
        self::assertSame(file_get_contents($this->directory . '/public.key'), $keyManager->getPublicKey()->getKeyContents());
        $keyManager->getEncryptionKey();
        self::assertDirectoryDoesNotExist($this->directory . '/unused');
    }

    /**
     * @param array<string, string|null> $settings
     */
    private function keyManager(array $settings = []): KeyManager
    {
        $keyManager = new KeyManager();
        $this->inject($keyManager, 'settings', $settings + [
            'privateKeyPath' => $this->directory . '/private.key',
            'publicKeyPath' => $this->directory . '/public.key',
            'encryptionKeyPath' => $this->directory . '/encryption.key',
            'privateKey' => null,
            'publicKey' => null,
            'encryptionKey' => null,
        ]);
        return $keyManager;
    }
}
