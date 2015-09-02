package org.xacml4j.opensaml;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.security.credential.Credential;

import com.google.common.collect.ImmutableList;

@RunWith(MockitoJUnitRunner.class)
public class DefaultIDPConfigurationTest {

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@BeforeClass
	public static void init() throws ConfigurationException {
		DefaultBootstrap.bootstrap();
	}

	@Test
	public void testGetSigningCredentialBackwardCompatibility() throws Exception {
		Credential cred1 = mock(Credential.class);
		Credential cred2 = mock(Credential.class);
		MetadataProvider metadata = mock(MetadataProvider.class);

		when(metadata.getEntityDescriptor("testEntityId")).thenReturn(mock(EntityDescriptor.class));

		DefaultIDPConfiguration idpConfiguration = new DefaultIDPConfiguration("testEntityId", metadata,
				ImmutableList.of(cred1, cred2));

		assertThat(idpConfiguration.getSigningCredential(), is(sameInstance(cred1)));
	}

	@Test
	public void testGetSigningCredentialsForwardCompatibility() throws Exception {
		Credential cred1 = mock(Credential.class);
		MetadataProvider metadata = mock(MetadataProvider.class);

		when(metadata.getEntityDescriptor("testEntityId")).thenReturn(mock(EntityDescriptor.class));

		DefaultIDPConfiguration idpConfiguration = new DefaultIDPConfiguration("testEntityId", metadata,
				cred1);

		List<Credential> signingCredentials = idpConfiguration.getSigningCredentials();
		assertThat(signingCredentials, is(notNullValue()));
		assertThat(signingCredentials.size(), is(1));
		assertThat(signingCredentials.get(0), is(sameInstance(cred1)));
	}

	@Test
	public void testConstructWithNullIdpSigningCredentials() throws MetadataProviderException {
		exception.expect(NullPointerException.class);
		exception.expectMessage("'idpSigningCredentials' is null.");

		new DefaultIDPConfiguration("testEntityId", mock(MetadataProvider.class), (List<Credential>) null);
	}

	@Test
	public void testConstructWithEmptyIdpSigningCredentials() throws MetadataProviderException {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("'idpSigningCredentials' is empty.");

		new DefaultIDPConfiguration("testEntityId", mock(MetadataProvider.class),
				ImmutableList.<Credential> of());
	}
}
