package org.eclipse.tractusx.wallet.stub.credential.impl;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.token.impl.TokenSettings;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;
import org.eclipse.tractusx.wallet.stub.utils.impl.DeterministicECKeyPairGenerator;
import org.eclipse.edc.iam.did.spi.document.VerificationMethod;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class CredentialServiceImplTest {

    @Mock
    private Storage storage;

    @Mock
    private KeyService keyService;

    @Mock
    private DidDocumentService didDocumentService;

    @Mock
    private WalletStubSettings walletStubSettings;

    @Mock
    private TokenSettings tokenSettings;

    @InjectMocks
    private CredentialServiceImpl credentialService;

    private KeyPair testKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        credentialService = new CredentialServiceImpl(
                storage,
                keyService,
                didDocumentService,
                walletStubSettings,
                tokenSettings
        );
        
        // Generate a test KeyPair for signing
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        testKeyPair = keyGen.generateKeyPair();
    }

    private DidDocument createDidDocument(String issuerId) {
        return DidDocument.Builder.newInstance()
                .id(issuerId)
                .verificationMethod(List.of(VerificationMethod.Builder.newInstance()
                        .id(issuerId + "#key-1")
                        .controller(issuerId)
                        .type("JsonWebKey2020")
                        .publicKeyJwk(Map.of(
                            "kty", "EC",
                            "crv", "secp256k1",
                            "use", "sig",
                            "kid", "key-1",
                            "alg", "ES256K"
                        ))
                        .build()))
                .build();
    }

    private void setupCommonMocks(String holderBpn, String type, String baseWalletBpn, String issuerId, String holderId) {
        // Mock WalletStubSettings
        when(walletStubSettings.baseWalletBPN()).thenReturn(baseWalletBpn);
        
        // Mock Storage to return empty
        when(storage.getCredentialsByHolderBpnAndType(holderBpn, type))
                .thenReturn(Optional.empty());
        
        // Mock DidDocumentService with proper VerificationMethod
        DidDocument issuerDidDoc = createDidDocument(issuerId);

        DidDocument holderDidDoc = DidDocument.Builder.newInstance()
                .id(holderId)
                .build();
        
        when(didDocumentService.getDidDocument(baseWalletBpn)).thenReturn(issuerDidDoc);
        when(didDocumentService.getDidDocument(holderBpn)).thenReturn(holderDidDoc);
    }

    @Test
    void getVerifiableCredentialByHolderBpnAndTypeAsJwt_returnsExistingJwt() {
        // Given
        String holderBpn = "BPNL000000000001";
        String type = "MembershipCredential";
        String expectedJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";

        when(storage.getCredentialsAsJwtByHolderBpnAndType(holderBpn, type))
                .thenReturn(Optional.of(expectedJwt));

        // When
        String actualJwt = credentialService.getVerifiableCredentialByHolderBpnAndTypeAsJwt(holderBpn, type);

        // Then
        assertEquals(expectedJwt, actualJwt);
    }

    @Test
    void getVerifiableCredentialByHolderBpnAndTypeAsJwt_createsNewJwt() throws Exception {
        // Given
        String holderBpn = "BPNL000000000001";
        String type = "MembershipCredential";
        String baseWalletBpn = "BPNL000000000000";
        String issuerId = "did:web:test-issuer";
        String holderId = "did:web:test-holder";

        // Mock WalletStubSettings
        when(walletStubSettings.baseWalletBPN()).thenReturn(baseWalletBpn);
        
        // Mock Storage to return empty for JWT
        when(storage.getCredentialsAsJwtByHolderBpnAndType(holderBpn, type))
                .thenReturn(Optional.empty());
        
        // Mock Storage to return empty for credentials to trigger new credential creation
        when(storage.getCredentialsByHolderBpnAndType(holderBpn, type))
                .thenReturn(Optional.empty());
        
        // Mock void methods using doNothing()
        doNothing().when(storage).saveCredentials(
            org.mockito.ArgumentMatchers.anyString(), 
            org.mockito.ArgumentMatchers.any(CustomCredential.class), 
            org.mockito.ArgumentMatchers.anyString(), 
            org.mockito.ArgumentMatchers.anyString());
                
        doNothing().when(storage).saveCredentialAsJwt(
            org.mockito.ArgumentMatchers.anyString(), 
            org.mockito.ArgumentMatchers.anyString(), 
            org.mockito.ArgumentMatchers.anyString(), 
            org.mockito.ArgumentMatchers.anyString());

        // Use DeterministicECKeyPairGenerator to get an ECDSA key pair
        KeyPair testKeyPair = DeterministicECKeyPairGenerator.createKeyPair(baseWalletBpn, "test");
        
        // Mock KeyService to return our test key pair
        when(keyService.getKeyPair(baseWalletBpn)).thenReturn(testKeyPair);

        // Mock DidDocumentService
        DidDocument issuerDidDoc = createDidDocument(issuerId);

        DidDocument holderDidDoc = DidDocument.Builder.newInstance()
                .id(holderId)
                .build();
        
        when(didDocumentService.getDidDocument(baseWalletBpn)).thenReturn(issuerDidDoc);
        when(didDocumentService.getDidDocument(holderBpn)).thenReturn(holderDidDoc);

        // Mock TokenSettings
        when(tokenSettings.tokenExpiryTime()).thenReturn(60);

        // When
        String actualJwt = credentialService.getVerifiableCredentialByHolderBpnAndTypeAsJwt(holderBpn, type);

        // Then
        assertTrue(actualJwt != null && !actualJwt.isEmpty(), "JWT should not be null or empty");
        
        // Verify the JWT can be parsed and contains expected claims
        SignedJWT parsedJwt = SignedJWT.parse(actualJwt);
        JWTClaimsSet claims = parsedJwt.getJWTClaimsSet();
        
        assertEquals(issuerId, claims.getIssuer());
        assertEquals(issuerId, claims.getSubject());
        assertEquals(holderBpn, claims.getClaim(Constants.BPN));
        assertTrue(claims.getAudience().containsAll(List.of(issuerId, holderId)));
        
        // Verify signature
        ECPublicKey publicKey = (ECPublicKey) testKeyPair.getPublic();
        ECDSAVerifier verifier = new ECDSAVerifier(publicKey);
        verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
        assertTrue(parsedJwt.verify(verifier), "JWT signature verification failed");
    }

    @Test
    void getVerifiableCredentialByHolderBpnAndType_createsBpnCredential() throws Exception {
        // Given
        String holderBpn = "BPNL000000000001";
        String type = Constants.BPN_CREDENTIAL;
        String baseWalletBpn = "BPNL000000000000";
        String issuerId = "did:web:test-issuer";
        String holderId = "did:web:test-holder";

        setupCommonMocks(holderBpn, type, baseWalletBpn, issuerId, holderId);

        // When
        CustomCredential credential = credentialService.getVerifiableCredentialByHolderBpnAndType(holderBpn, type);

        // Then
        assertNotNull(credential);
        assertEquals(issuerId, credential.get("issuer"));
        Map<String, Object> credentialSubject = (Map<String, Object>) credential.get("credentialSubject");
        assertEquals(holderBpn, credentialSubject.get("bpn"));
        assertEquals(holderId, credentialSubject.get("id"));
        assertEquals(holderBpn, credentialSubject.get("holderIdentifier"));
        
        // Verify storage was called
        verify(storage).saveCredentials(anyString(), any(CustomCredential.class), eq(holderBpn), eq(type));
    }

    @Test
    void getVerifiableCredentialByHolderBpnAndType_createsDataExchangeCredential() throws Exception {
        // Given
        String holderBpn = "BPNL000000000001";
        String type = Constants.DATA_EXCHANGE_CREDENTIAL;
        String baseWalletBpn = "BPNL000000000000";
        String issuerId = "did:web:test-issuer";
        String holderId = "did:web:test-holder";

        setupCommonMocks(holderBpn, type, baseWalletBpn, issuerId, holderId);

        // When
        CustomCredential credential = credentialService.getVerifiableCredentialByHolderBpnAndType(holderBpn, type);

        // Then
        assertNotNull(credential);
        assertEquals(issuerId, credential.get("issuer"));
        Map<String, Object> credentialSubject = (Map<String, Object>) credential.get("credentialSubject");
        assertEquals(holderId, credentialSubject.get("id"));
        assertEquals(holderBpn, credentialSubject.get("holderIdentifier"));
        assertEquals("UseCaseFramework", credentialSubject.get("group"));
        assertEquals("DataExchangeGovernance", credentialSubject.get("useCase"));
        assertEquals("https://example.org/temp-1", credentialSubject.get("contractTemplate"));
        assertEquals("1.0", credentialSubject.get("contractVersion"));
        
        // Verify storage was called
        verify(storage).saveCredentials(anyString(), any(CustomCredential.class), eq(holderBpn), eq(type));
    }

    @Test
    void getVerifiableCredentialByHolderBpnAndType_throwsExceptionForUnsupportedType() {
        // Given
        String holderBpn = "BPNL000000000001";
        String type = "UnsupportedType";
        String baseWalletBpn = "BPNL000000000000";
        String issuerId = "did:web:test-issuer";
        String holderId = "did:web:test-holder";

        setupCommonMocks(holderBpn, type, baseWalletBpn, issuerId, holderId);

        // When/Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> credentialService.getVerifiableCredentialByHolderBpnAndType(holderBpn, type)
        );
        
        assertEquals("vc type -> " + type + " is not supported", exception.getMessage());
    }

    @Test
    void getVerifiableCredentialByHolderBpnAndType_returnsExistingCredential() {
        // Given
        String holderBpn = "BPNL000000000001";
        String type = "MembershipCredential";
        CustomCredential existingCredential = new CustomCredential();
        existingCredential.put("test", "value");
        
        // Mock Storage to return existing credential
        when(storage.getCredentialsByHolderBpnAndType(holderBpn, type))
                .thenReturn(Optional.of(existingCredential));

        // When
        CustomCredential result = credentialService.getVerifiableCredentialByHolderBpnAndType(holderBpn, type);

        // Then
        assertSame(existingCredential, result);
        assertEquals("value", result.get("test"));
        
        // Verify no other interactions
        verifyNoMoreInteractions(keyService, didDocumentService);
    }
}
