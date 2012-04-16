/**
 * Copyright (C) 2011 meltmedia <john.trimble@meltmedia.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.meltmedia.maven.plugins.meltcloud

import org.apache.maven.artifact.Artifact
import org.apache.maven.artifact.factory.ArtifactFactory
import org.apache.maven.artifact.metadata.ArtifactMetadataSource
import org.apache.maven.artifact.repository.ArtifactRepository
import org.apache.maven.artifact.resolver.ArtifactNotFoundException
import org.apache.maven.artifact.resolver.ArtifactResolutionException
import org.apache.maven.artifact.resolver.ArtifactResolver
import org.apache.maven.artifact.versioning.InvalidVersionSpecificationException
import org.apache.maven.artifact.versioning.VersionRange
import org.apache.maven.model.Dependency
import org.apache.maven.plugin.MojoExecutionException
import org.apache.maven.project.MavenProject
import org.codehaus.gmaven.common.ArtifactItem
import org.codehaus.gmaven.mojo.GroovyMojo
import org.codehaus.plexus.util.FileUtils;

import com.amazonaws.auth.AWSCredentials
import com.amazonaws.auth.PropertiesCredentials
import com.amazonaws.services.cloudformation.AmazonCloudFormation
import com.amazonaws.services.cloudformation.AmazonCloudFormationClient
import com.amazonaws.services.cloudformation.model.CreateStackRequest
import com.amazonaws.services.cloudformation.model.CreateStackResult
import com.amazonaws.services.cloudformation.model.DeleteStackRequest
import com.amazonaws.services.cloudformation.model.DescribeStacksRequest
import com.amazonaws.services.cloudformation.model.Parameter
import com.amazonaws.services.cloudformation.model.Stack
import com.amazonaws.services.cloudformation.model.StackStatus;
import com.amazonaws.services.ec2.AmazonEC2
import com.amazonaws.services.ec2.AmazonEC2Client
import com.amazonaws.services.ec2.model.AssociateAddressRequest
import com.amazonaws.services.ec2.model.DisassociateAddressRequest

/**
 * Creates a new set of AWS resources as specified in a provided CloudFormation template. After creating the resources,
 * it will assign an EIPs specified EC2 instances defined in the template, and removes any existing CloudFormation 
 * stacks that specify the same 'ProvisioningGroup' output value. If the new stack fails to start for whatever reason, 
 * no existing stacks will be removed and no EIPs will be associated/disassociated.
 * 
 * @author John Trimble <john.trimble@meltmedia.com>
 * 
 * @aggregator
 * @goal deploy
 */
class DeployMojo extends GroovyMojo {

  /**
   * @parameter expression="${project}"
   * @required
   * @readonly
   *
   * @noinspection UnusedDeclaration
   */
  protected MavenProject project;

  /**
   * @component
   * @readonly
   * @required
   *
   * @noinspection UnusedDeclaration
   */
  ArtifactFactory artifactFactory

  /**
   * @component
   * @readonly
   * @required
   *
   * @noinspection UnusedDeclaration
   */
  ArtifactResolver artifactResolver

  /**
   * @component
   * @readonly
   * @required
   *
   * @noinspection UnusedDeclaration
   */
  ArtifactMetadataSource artifactMetadataSource

  /**
   * @parameter expression="${localRepository}"
   * @readonly
   * @required
   *
   * @noinspection UnusedDeclaration
   */
  ArtifactRepository artifactRepository

  /**
   * @parameter expression="${project.pluginArtifactRepositories}"
   * @required
   * @readonly
   *
   * @noinspection UnusedDeclaration
   */
  List remoteRepositories

  /**
   * File containing AWS credentials in the following format:
   * accessKey=YOUR_ACCESS_KEY
   * secretKey=YOUR_SECRET_KEY
   * 
   * @parameter expression="${user.home}/.aws_credentials"
   */
  File credentialsFile

  /**
   * Maps stack output parameters representing EC2 instance IDs to EIPs. For example, if a given stack has an output 
   * parameter 'MyEc2InstanceId', and the value of the parameter is an EC2 instance ID, then the following would map
   * that EC2 Instance to the EIP 50.18.176.103:
   * &lt;configuration&gt;
   * ...
   *   &lt;ec2EipMappings&gt;
   *     $lt;MyEc2InstanceId&gt;50.18.176.103$lt;/MyEc2InstanceId&gt;
   *   $lt;/ec2EipMappings&gt;
   * ...
   * &lt;/configuration&gt;
   * 
   * @parameter
   */
  Map ec2EipMappings

  /**
   * @parameter default-value="development-"
   */
  String stackPrefix

  /**
   * @parameter default-value="ProvisioningGroup"
   */
  String provisioningGroupOutputKey
  
  /**
   * The maximum number of active stacks allowed for the AWS account. This is a fail-safe to insure that large numbers
   * of AWS stacks are not created by accident.
   * 
   * @parameter default-value="10" 
   */
  Integer maximumNumberOfActiveStacks

  /**
   * The provisioning group to use for the stack. For any given provisioning group there should be at most one active 
   * stack. After the specified stack is created, any other active stacks that are part of this provisioning group will 
   * be removed.
   * 
   * @parameter default-value="development"
   */
  String provisioningGroup

  /**
   * The AWS region to use.
   * 
   * @parameter default-value="us-west-1"
   */
  String region

  /**
   * Additional input parameters for the CloudFormation template.
   * 
   * @parameter
   */
  Map parameters
  
  /**
   * Flag indicating whether or not the output parameters should be dumped.
   * 
   * @parameter default-value="false"
   */
  boolean dumpOutputs
  
  /**
   * The file to dump the stack's output parameters to. This will only be used if <code>dumpOutputs</code> is true.
   * 
   * @parameter expression="${project.build.outputDirectory}/cfoutputs.properties"
   */
  File dumpOutputsFile

  /**
   * The CloudFormation template file.
   * 
   * @parameter expression="${project.build.outputDirectory}/provision.template"
   */
 File template
  
  /**
   * The Maven artifact for the CloudFormation template.
   * @parameter
   */
  ArtifactItem templateArtifact

  /**
   * CloudFormation instance to use.
   */
  AmazonCloudFormation cloudFormation
  
  /**
   * EC2 instance to use.
   */
  AmazonEC2 ec2
  
  // Mapping of regions to AWS endpoints.
  private Map regionEndpoints = [
    'us-west-1': [
      'cloudformation': 'cloudformation.us-west-1.amazonaws.com', 
      'ec2': 'ec2.us-west-1.amazonaws.com'],
    'us-east-1': [
      'cloudformation': 'cloudformation.us-east-1.amazonaws.com', 
      'ec2': 'ec2.us-east-1.amazonaws.com']]
  
  /**
   * Creates a CloudFormation client using the given credentials and endpoint.
   * 
   * @param credentials
   * @param endpoint
   * @return
   */
  AmazonCloudFormation createCloudFormation(AWSCredentials credentials, String endpoint) {
    AmazonCloudFormationClient cf = new AmazonCloudFormationClient(credentials)
    cf.endpoint = endpoint
    return cf
  }
  
  /**
   * Creates an EC2 client using the given credentials and endpoint.
   * 
   * @param credentials
   * @param endpoint
   * @return
   */
  AmazonEC2 createEC2(AWSCredentials credentials, String endpoint) {
    AmazonEC2Client ec2 = new AmazonEC2Client(credentials)
    ec2.endpoint = endpoint
    return ec2
  }
  
  void execute() {
    // Find template
    if( templateArtifact ) {
      Artifact artifact = getArtifact(templateArtifact)
      template = artifact.file
    }
    
    if( !template ) {
      fail("No template specified.")
    }
    
    if( template && !template.exists() ) {
      fail("Template file '${template.path}' does not exist.")
    }

    // Create AWS clients if necessary.
    if( !cloudFormation || !ec2 ) {
      // Find and load AWS credentials
      if( !credentialsFile.exists() )
        fail("Could not find credentials file ${credentialsFile.path}")
      AWSCredentials credentials = new PropertiesCredentials(credentialsFile)
      
      // Create CloudFormation client if necessary.
      if( !cloudFormation ) {
        cloudFormation = createCloudFormation(credentials, regionEndpoints[region]['cloudformation'])
      }
      
      // Create EC2 client if necessary.
      if( !ec2 ) {
        ec2 = createEC2(credentials, regionEndpoints[region]['ec2'])
      }
    }
    
    // Make sure a maximum number of active stacks was set for our sanity check
    if( !maximumNumberOfActiveStacks ) {
      fail('The maximum number of active stacks was not specified.')
    }
    
    // Sanity check to insure we don't make thousands of these by accident
    List existingStacks = getFullStacks(cloudFormation, cloudFormation.describeStacks().stacks).grep({
      // Ignore anything either deleted or being deleted
      !(StackStatus.fromValue(it.stackStatus) in [
        StackStatus.DELETE_IN_PROGRESS,
        StackStatus.DELETE_COMPLETE
      ])
    })
    if( existingStacks && existingStacks.size() > maximumNumberOfActiveStacks ) {
      fail("Exceeded maximum allowed active stacks. Maximum is ${maximumNumberOfActiveStacks} and there are currently ${existingStacks.size()}.")
    }

    // Create CloudFormation parameter list
    List cfParameters = []
    this.parameters.collect cfParameters, { key, value -> new Parameter(parameterKey:key, parameterValue: value) }
    if( provisioningGroup )
      cfParameters << new Parameter(parameterKey:'ProvisioningGroup', parameterValue: provisioningGroup)
    
    // Create new stack for this provisioningGroup
    String stackId = cloudFormation.createStack(new CreateStackRequest(stackName:"${stackPrefix}${new Date().format('yyyyMMddHHmmss')}", templateBody:template.text, timeoutInMinutes: 30, parameters: cfParameters)).stackId
    log.info "Creating stack ${stackId} for provisioning group ${provisioningGroup}"

    // Poll status of stack until CREATE_COMPLETE or some other non-CREATE_IN_PROGRESS status
    Stack stack = null
    for( ;; ) {
      stack = cloudFormation.describeStacks(new DescribeStacksRequest(stackName: stackId)).stacks.find { it }
      if( StackStatus.valueOf(stack.stackStatus) == StackStatus.CREATE_COMPLETE ) {
        break
      } else if( StackStatus.valueOf(stack.stackStatus) != StackStatus.CREATE_IN_PROGRESS ) {
        fail("Failed to create stack ${stack}")
      }
      Thread.currentThread().sleep 60*1000
    }

    // Stack created, w00t!
    log.info "Successfully created stack ${stack.stackName}"
    
    // Dump outputs
    try {
      if( dumpOutputs && dumpOutputsFile ) {
        log.info "Dumping stack output parameters to ${dumpOutputsFile.path}"
        // Create the outputs file if needed
        if( !dumpOutputsFile.exists() ) {
          File parentDir = dumpOutputsFile.getAbsoluteFile().getParentFile()
          if( parentDir && !parentDir.exists() ) {
            log.debug "Creating parent directory '${parentDir.path}'"
            parentDir.mkdirs()
          }
          log.debug "Creating dumpOutputsFile '${dumpOutputsFile.path}'"
          dumpOutputsFile.createNewFile()
        }
        Properties dumpProps = new Properties()
        stack.outputs.each { dumpProps.put(it.outputKey, it.outputValue) }.each { log.info "Output Parameter: ${it.outputKey} -> ${it.outputValue}" }
        dumpOutputsFile.withOutputStream { dumpProps.store it, "" }
      }
    } catch( Exception e ) {
      log.warn "Error encountered while dumping ouptut parameters for stack ${stack.stackId}."
      log.info "Deleting stack ${stack.stackId}."
      cloudFormation.deleteStack new DeleteStackRequest(stackName: stack.stackId)
      throw new MojoExecutionException("Error encountered while dumping output parameters for stack ${stack.stackId}", e)
    }
    
    // Associate EIPs
    try {
      ec2EipMappings.each { String ec2InstanceIdOutputKey, String eip ->
        // Grab the EC2 instance's identifier
        String ec2InstanceId = stack.outputs.find({ it.outputKey == ec2InstanceIdOutputKey })?.outputValue
        if( !ec2InstanceId ) {
          log.info "Could not find the EC2 instance ID using key '${ec2InstanceIdOutputKey}'"
          fail('Could not find the EC2 instance ID')
        }
  
        if( eip ) {
          log.info "Mapping Elastic IPs to EC2 instances."
          // Reassociate EIP
          ec2.disassociateAddress new DisassociateAddressRequest(publicIp: eip) // out with the old
          ec2.associateAddress new AssociateAddressRequest(instanceId: ec2InstanceId, publicIp: eip) // in with the new
          log.info "Successfully mapped EIP ${eip} to instance ${ec2InstanceId}"
        }
      }
    } catch( Exception e ) {
      // We created the stack but somehow failed to associated EIPs.
      log.warn "Error encountered while mapping EIPs for stack ${stack.stackId}."
      log.info "Deleting stack ${stack.stackId}."
      cloudFormation.deleteStack new DeleteStackRequest(stackName: stack.stackId)
      throw new MojoExecutionException('Error encountered while mapping EIPs.', e)
    }
    
    // Delete existing stacks in the provisioning group
    try {
      log.info "Deleting old stacks in the provisioning group '${provisioningGroup}'."
      getFullStacks(cloudFormation, cloudFormation.describeStacks().stacks).grep {
        // Select only development stacks
        it.outputs.find { it.outputKey == provisioningGroupOutputKey && it.outputValue == provisioningGroup }
      }.grep {
        // Ignore anything either deleted or being deleted
        !(StackStatus.valueOf(it.stackStatus) in [
          StackStatus.DELETE_IN_PROGRESS, 
          StackStatus.DELETE_COMPLETE
        ])
      }.grep {
        // Lets not delete the stack we just frak'n created
        it.stackId != stackId
      }.each {
        // Delete the old stacks we've just replaced
        log.info "Deleting defunct stack '${it}'"
        cloudFormation.deleteStack new DeleteStackRequest(stackName: it.stackId)
      }
    } catch( Exception e ) {
      // We created the stack but somehow failed to remove defunct stacks.
      log.warn "Error encountered while deleting old stacks for provisioning group '${provisioningGroup}'."
      log.info "Deleting stack ${stack.stackId}."
      cloudFormation.deleteStack new DeleteStackRequest(stackName: stack.stackId)
      throw new MojoExecutionException("Error encountered while deleting old stacks for provisioning group '${provisioningGroup}'.", e)
    }
  }
  
  /**
   * Transforms a list of stacks into a list stacks with all fields fully populated.
   */
  List<Stack> getFullStacks(AmazonCloudFormation cf, List<Stack> stacks) {
    stacks.collect { cf.describeStacks(new DescribeStacksRequest(stackName: it.stackId)).stacks }.flatten()
  }

  Artifact getArtifact(ArtifactItem item) {
    if( !item )
      fail('Cannot get an Artifact instance for a null ArtifactItem.')
    
    // Fill in artifact version if missing
    if( !item.version ) {
      (project.dependencies + project.dependencyManagement.dependencies).find { dep -> ['groupId','artifactId','type'].every { item."$it" == dep."$it" } }?.with { item.version = version }
    }
    
    // Complain if version still missing
    if( !item.version ) {
      fail("Unable to find artifact version of ${item.groupId}:${item.artifactId} in either projects dependencies or dependency management.")
    }
    
    // Create dependency
    Artifact artifact = artifactFactory.createDependencyArtifact(
        item.groupId, 
        item.artifactId, 
        VersionRange.createFromVersionSpec(item.version), 
        item.type, 
        item.classifier, 
        Artifact.SCOPE_PROVIDED)
      
    // Resolve the artifact        
    artifactResolver.resolve(
      artifact, 
      project.remoteArtifactRepositories, 
      artifactRepository)
    
    return artifact
  }
}
