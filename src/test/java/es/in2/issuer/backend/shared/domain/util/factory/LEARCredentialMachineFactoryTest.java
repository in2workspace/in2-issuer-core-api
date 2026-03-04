package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.CredentialSerializationException;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.LEARCredentialMachineJwtPayload;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.machine.LEARCredentialMachine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LEARCredentialMachineFactoryTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private IssuerFactory issuerFactory;

    @InjectMocks
    private LEARCredentialMachineFactory learCredentialMachineFactory;

    @Test
    void mapStringToLEARCredentialMachine_shouldDoSuccessfully() throws Exception {
        String credentialV1 = "{\"@context\": \"https://trust-framework.dome-marketplace.eu/credentials/learcredentialmachine/v1\"}";
        LEARCredentialMachine expectedMachine = mock(LEARCredentialMachine.class);

        when(objectMapper.readValue(credentialV1, LEARCredentialMachine.class)).thenReturn(expectedMachine);

        LEARCredentialMachine result = learCredentialMachineFactory.mapStringToLEARCredentialMachine(credentialV1);

        assertThat(expectedMachine).isEqualTo(result);
    }

    @Test
    void testMapAndBuildLEARCredentialMachine() throws JsonProcessingException {
        // Arrange
        String json = "{\"test\": \"test\"}";
        JsonNode jsonNode = new ObjectMapper().readTree(json); // use real ObjectMapper to create JsonNode

        CredentialStatus credentialStatus = mock(CredentialStatus.class);

        LEARCredentialMachine.CredentialSubject.Mandate mockMandate =
                mock(LEARCredentialMachine.CredentialSubject.Mandate.class);
        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mockMandatee =
                mock(LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.class);
        LEARCredentialMachine.CredentialSubject.Mandate.Mandator mockMandator =
                mock(LEARCredentialMachine.CredentialSubject.Mandate.Mandator.class);

        when(objectMapper.convertValue(jsonNode, LEARCredentialMachine.CredentialSubject.Mandate.class))
                .thenReturn(mockMandate);

        when(mockMandate.mandatee()).thenReturn(mockMandatee);
        when(mockMandate.mandator()).thenReturn(mockMandator);

        when(mockMandator.organizationIdentifier()).thenReturn("orgId");
        when(mockMandatee.domain()).thenReturn("example-domain");

        when(objectMapper.writeValueAsString(any(LEARCredentialMachine.class))).thenReturn(json);

        // Act
        Mono<CredentialProcedureCreationRequest> result =
                learCredentialMachineFactory.mapAndBuildLEARCredentialMachine(
                        "proc-123",
                        jsonNode,
                        credentialStatus,
                        "S",
                        ""
                );

        // Assert
        StepVerifier.create(result)
                .assertNext(req -> {
                    assertThat(req.procedureId()).isEqualTo("proc-123");
                    assertThat(req.organizationIdentifier()).isEqualTo("orgId");
                    assertThat(req.operationMode()).isEqualTo("S");
                    assertThat(req.email()).isEmpty();
                    assertThat(req.credentialDecoded()).isEqualTo(json);
                    assertThat(req.subject()).isEqualTo("example-domain");
                })
                .verifyComplete();
    }

    @Test
    void convertLEARCredentialMachineInToString_whenWriteFails_emitsCredentialSerializationException() throws Exception {
        LEARCredentialMachine credential = mock(LEARCredentialMachine.class);
        when(objectMapper.writeValueAsString(any(LEARCredentialMachine.class)))
                .thenThrow(new JsonProcessingException("error") {
                });

        Method m = LEARCredentialMachineFactory.class
                .getDeclaredMethod("convertLEARCredentialMachineInToString", LEARCredentialMachine.class);
        m.setAccessible(true);

        Object invokeResult = m.invoke(learCredentialMachineFactory, credential);

        assertThat(invokeResult).isInstanceOf(Mono.class);

        StepVerifier.create((Mono<?>) invokeResult)
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(CredentialSerializationException.class);
                    assertThat(ex.getMessage()).isEqualTo("Error serializing LEARCredentialMachine to string.");
                })
                .verify();
    }

    @Test
    void convertLEARCredentialMachineJwtPayloadInToString_whenWriteFails_emitsCredentialSerializationException() throws Exception {
        LEARCredentialMachineJwtPayload payload = mock(LEARCredentialMachineJwtPayload.class);
        when(objectMapper.writeValueAsString(any(LEARCredentialMachineJwtPayload.class)))
                .thenThrow(new JsonProcessingException("error") {
                });

        Mono<String> result = learCredentialMachineFactory.convertLEARCredentialMachineJwtPayloadInToString(payload);

        StepVerifier.create(result)
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(CredentialSerializationException.class);
                    assertThat(ex.getMessage()).isEqualTo("Error serializing LEARCredentialMachine JWT payload to string.");
                })
                .verify();
    }

    @Test
    void mapCredentialAndBindIssuerInToTheCredential_shouldBindDetailedIssuerAndSerialize() throws Exception {
        // Arrange
        String decoded = "{\"@context\":\"https://trust-framework.dome-marketplace.eu/credentials/learcredentialmachine/v1\"}";
        String procedureId = "proc-123";
        DetailedIssuer detailedIssuer = mock(DetailedIssuer.class);

        LEARCredentialMachine baseMachine = mock(LEARCredentialMachine.class);
        when(objectMapper.readValue(decoded, LEARCredentialMachine.class)).thenReturn(baseMachine);
        when(issuerFactory.createDetailedIssuerAndNotifyOnError(procedureId, ""))
                .thenReturn(Mono.just(detailedIssuer));

        // capture the final object being serialized to check the issuer is set
        ArgumentCaptor<LEARCredentialMachine> captor = ArgumentCaptor.forClass(LEARCredentialMachine.class);
        when(objectMapper.writeValueAsString(any(LEARCredentialMachine.class))).thenReturn("{\"ok\":true}");

        // Act
        Mono<String> mono = learCredentialMachineFactory.mapCredentialAndBindIssuerInToTheCredential(decoded, procedureId, "");

        // Assert
        StepVerifier.create(mono)
                .expectNext("{\"ok\":true}")
                .verifyComplete();

        verify(objectMapper).writeValueAsString(captor.capture());
        LEARCredentialMachine serialized = captor.getValue();
        assertThat(detailedIssuer).isEqualTo(serialized.issuer());
        verify(issuerFactory).createDetailedIssuerAndNotifyOnError(procedureId, "");
    }

    @Test
    void buildLEARCredentialMachineJwtPayload_shouldUseDetailedIssuerIdAndSubject() {
        // Arrange
        DetailedIssuer issuer = mock(DetailedIssuer.class);
        when(issuer.getId()).thenReturn("issuer-id-xyz");

        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.builder()
                        .id("mandatee-123")
                        .build();

        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandatee(mandatee)
                        .build();

        LEARCredentialMachine.CredentialSubject subject =
                LEARCredentialMachine.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();

        LEARCredentialMachine machine = LEARCredentialMachine.builder()
                .issuer(issuer)
                .validFrom("2025-01-01T00:00:00Z")
                .validUntil("2025-12-31T23:59:59Z")
                .credentialSubject(subject)
                .build();

        // Act
        Mono<LEARCredentialMachineJwtPayload> mono = learCredentialMachineFactory.buildLEARCredentialMachineJwtPayload(machine);

        // Assert
        StepVerifier.create(mono)
                .assertNext(payload -> {
                    assertThat(payload.issuer()).isEqualTo("issuer-id-xyz");
                    assertThat(payload.subject()).isEqualTo("mandatee-123");

                    org.junit.jupiter.api.Assertions.assertTrue(payload.expirationTime() > 0);
                    org.junit.jupiter.api.Assertions.assertTrue(payload.issuedAt() > 0);
                    org.junit.jupiter.api.Assertions.assertTrue(payload.notValidBefore() > 0);
                })
                .verifyComplete();
    }

    @Test
    void bindCryptographicCredentialSubjectId_shouldBindSubjectIdAndSerialize() throws Exception {
        // Arrange
        String decoded = "{\"any\":\"json\"}";

        String mandateeId = "did:key:mandatee-id-xyz";
        String expectedJson = "{\"ok\":true}";

        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.builder()
                        .id(mandateeId)
                        .build();

        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandatee(mandatee)
                        .build();

        LEARCredentialMachine.CredentialSubject subject =
                LEARCredentialMachine.CredentialSubject.builder()
                        .id("old-subject")
                        .mandate(mandate)
                        .build();

        LEARCredentialMachine decodedMachine = LEARCredentialMachine.builder()
                .credentialSubject(subject)
                .build();

        when(objectMapper.readValue(decoded, LEARCredentialMachine.class))
                .thenReturn(decodedMachine, decodedMachine);

        ArgumentCaptor<LEARCredentialMachine> captor = ArgumentCaptor.forClass(LEARCredentialMachine.class);
        when(objectMapper.writeValueAsString(captor.capture())).thenReturn(expectedJson);

        // Act
        Mono<String> result = learCredentialMachineFactory.bindCryptographicCredentialSubjectId(decoded);

        // Assert
        StepVerifier.create(result)
                .expectNext(expectedJson)
                .verifyComplete();

        LEARCredentialMachine serialized = captor.getValue();
        assertThat(mandateeId).isEqualTo(serialized.credentialSubject().id());
        assertThat(mandate).isEqualTo(serialized.credentialSubject().mandate());

        verify(objectMapper, times(2)).readValue(decoded, LEARCredentialMachine.class);
        verify(objectMapper, times(1)).writeValueAsString(any(LEARCredentialMachine.class));
    }


    @Test
    void bindCryptographicCredentialSubjectId_whenWriteFails_emitsCredentialSerializationException() throws Exception {
        // Arrange
        String decoded = "{\"any\":\"json\"}";

        String mandateeId = "did:key:mandatee-id-xyz";

        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.builder()
                        .id(mandateeId)
                        .build();

        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandatee(mandatee)
                        .build();

        LEARCredentialMachine.CredentialSubject subject =
                LEARCredentialMachine.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();

        LEARCredentialMachine decodedMachine = LEARCredentialMachine.builder()
                .credentialSubject(subject)
                .build();

        when(objectMapper.readValue(decoded, LEARCredentialMachine.class)).thenReturn(decodedMachine);

        when(objectMapper.writeValueAsString(any(LEARCredentialMachine.class)))
                .thenThrow(new JsonProcessingException("write boom") {
                });

        // Act
        Mono<String> result = learCredentialMachineFactory.bindCryptographicCredentialSubjectId(decoded);

        // Assert
        StepVerifier.create(result)
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(CredentialSerializationException.class);
                    assertThat(ex.getMessage()).isEqualTo("Error serializing LEARCredentialMachine to string.");
                })
                .verify();
    }

    @Test
    void bindCryptographicCredentialSubjectId_whenReadValueFails_throwsInvalidCredentialFormatException() throws Exception {
        // Arrange
        String decoded = "bad-json";


        when(objectMapper.readValue(decoded, LEARCredentialMachine.class))
                .thenThrow(new JsonProcessingException("boom") {
                });

        org.junit.jupiter.api.Assertions.assertThrows(
                InvalidCredentialFormatException.class,
                () -> learCredentialMachineFactory.bindCryptographicCredentialSubjectId(decoded)
        );

        verify(objectMapper).readValue(decoded, LEARCredentialMachine.class);
        verify(objectMapper, never()).writeValueAsString(any());
    }

    @Test
    void bindCryptographicCredentialSubjectId_whenCredentialSubjectIsNull_throwsInvalidCredentialFormatException() throws Exception {
        // Arrange
        String decoded = "{\"any\":\"json\"}";

        LEARCredentialMachine decodedMachine = LEARCredentialMachine.builder()
                .credentialSubject(null)
                .build();

        when(objectMapper.readValue(decoded, LEARCredentialMachine.class))
                .thenReturn(decodedMachine);

        // Act & Assert
        assertThatExceptionOfType(InvalidCredentialFormatException.class)
                .isThrownBy(() -> learCredentialMachineFactory.bindCryptographicCredentialSubjectId(decoded));

        verify(objectMapper, times(2)).readValue(decoded, LEARCredentialMachine.class);
        verify(objectMapper, never()).writeValueAsString(any());
    }

    @Test
    void bindCryptographicCredentialSubjectId_whenMandateIsNull_throwsInvalidCredentialFormatException() throws Exception {
        // Arrange
        String decoded = "{\"any\":\"json\"}";

        LEARCredentialMachine.CredentialSubject subject =
                LEARCredentialMachine.CredentialSubject.builder()
                        .mandate(null)
                        .build();

        LEARCredentialMachine decodedMachine = LEARCredentialMachine.builder()
                .credentialSubject(subject)
                .build();

        when(objectMapper.readValue(decoded, LEARCredentialMachine.class))
                .thenReturn(decodedMachine);

        // Act & Assert
        assertThatExceptionOfType(InvalidCredentialFormatException.class)
                .isThrownBy(() -> learCredentialMachineFactory.bindCryptographicCredentialSubjectId(decoded));

        verify(objectMapper, times(2)).readValue(decoded, LEARCredentialMachine.class);
        verify(objectMapper, never()).writeValueAsString(any());
    }

    @Test
    void bindCryptographicCredentialSubjectId_whenMandateeIsNull_throwsInvalidCredentialFormatException() throws Exception {
        // Arrange
        String decoded = "{\"any\":\"json\"}";

        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandatee(null)
                        .build();

        LEARCredentialMachine.CredentialSubject subject =
                LEARCredentialMachine.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();

        LEARCredentialMachine decodedMachine = LEARCredentialMachine.builder()
                .credentialSubject(subject)
                .build();

        when(objectMapper.readValue(decoded, LEARCredentialMachine.class))
                .thenReturn(decodedMachine);

        // Act & Assert
        org.junit.jupiter.api.Assertions.assertThrows(
                InvalidCredentialFormatException.class,
                () -> learCredentialMachineFactory.bindCryptographicCredentialSubjectId(decoded)
        );

        verify(objectMapper, times(2)).readValue(decoded, LEARCredentialMachine.class);
        verify(objectMapper, never()).writeValueAsString(any());
    }

    @Test
    void bindCryptographicCredentialSubjectId_whenMandateeIdIsNull_throwsInvalidCredentialFormatException() throws Exception {
        // Arrange
        String decoded = "{\"any\":\"json\"}";

        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.builder()
                        .id(null)
                        .build();

        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandatee(mandatee)
                        .build();

        LEARCredentialMachine.CredentialSubject subject =
                LEARCredentialMachine.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();

        LEARCredentialMachine decodedMachine = LEARCredentialMachine.builder()
                .credentialSubject(subject)
                .build();

        when(objectMapper.readValue(decoded, LEARCredentialMachine.class))
                .thenReturn(decodedMachine);

        // Act & Assert
        org.junit.jupiter.api.Assertions.assertThrows(
                InvalidCredentialFormatException.class,
                () -> learCredentialMachineFactory.bindCryptographicCredentialSubjectId(decoded)
        );

        verify(objectMapper, times(2)).readValue(decoded, LEARCredentialMachine.class);
        verify(objectMapper, never()).writeValueAsString(any());
    }

    @Test
    void bindCryptographicCredentialSubjectId_whenMandateeIdIsBlank_throwsInvalidCredentialFormatException() throws Exception {
        // Arrange
        String decoded = "{\"any\":\"json\"}";
        String blankMandateeId = "";

        LEARCredentialMachine.CredentialSubject.Mandate.Mandatee mandatee =
                LEARCredentialMachine.CredentialSubject.Mandate.Mandatee.builder()
                        .id(blankMandateeId)
                        .build();

        LEARCredentialMachine.CredentialSubject.Mandate mandate =
                LEARCredentialMachine.CredentialSubject.Mandate.builder()
                        .mandatee(mandatee)
                        .build();

        LEARCredentialMachine.CredentialSubject subject =
                LEARCredentialMachine.CredentialSubject.builder()
                        .mandate(mandate)
                        .build();

        LEARCredentialMachine decodedMachine = LEARCredentialMachine.builder()
                .credentialSubject(subject)
                .build();

        when(objectMapper.readValue(decoded, LEARCredentialMachine.class))
                .thenReturn(decodedMachine);

        // Act & Assert
        org.junit.jupiter.api.Assertions.assertThrows(
                InvalidCredentialFormatException.class,
                () -> learCredentialMachineFactory.bindCryptographicCredentialSubjectId(decoded)
        );

        verify(objectMapper, times(2)).readValue(decoded, LEARCredentialMachine.class);
        verify(objectMapper, never()).writeValueAsString(any());
    }
}

