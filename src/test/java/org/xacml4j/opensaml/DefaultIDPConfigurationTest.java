package org.xacml4j.opensaml;

/*
 * #%L
 * XACML/OpenSAML Integration
 * %%
 * Copyright (C) 2009 - 2015 Xacml4J.org
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Lesser Public License for more details.
 * 
 * You should have received a copy of the GNU General Lesser Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/lgpl-3.0.html>.
 * #L%
 */

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
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.security.credential.Credential;

import com.google.common.collect.ImmutableList;

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
